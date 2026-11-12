package user_test

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	"gochen-iam/router"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func selfUserFixture(t *testing.T, env *userServiceTestEnv) *iamentity.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: env.rootScopeID,
		ManagedScopeID: env.rootScopeID, OwnerID: "owner", Username: "self", Email: "self@example.test", Password: string(hash), Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	return user
}

func selfUserContext(t *testing.T, env *userServiceTestEnv, subject string, system bool) context.Context {
	t.Helper()
	ctx, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: subject, IsSystem: system, ActiveScopeID: env.rootScopeID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(env.rootScopeID))
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestUserSelfRejectsUntrustedAndOtherSubjectsBeforeGormAccess(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := selfUserFixture(t, env)
	var reads, writes atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("user-self:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("user-self:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trusted := selfUserContext(t, env, "99", false)
	if _, err := env.userService.UserProfile(trusted, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UpdateProfile(trusted, user.ID, &svc.UpdateUserRequest{Avatar: "observed"}); err != nil {
		t.Fatal(err)
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatal("observers did not detect the successful real service")
	}
	reads.Store(0)
	writes.Store(0)
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(base, "99")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := hostauthz.WithPrincipal(base, hostauthz.Principal{SubjectID: "7", Permissions: []string{"*:*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{{nil, errors.InvalidInput}, {base, errors.Unauthorized}, {trace, errors.Unauthorized},
		{selfUserContext(t, env, "opaque", false), errors.Unauthorized}, {admin, errors.Forbidden}} {
		if _, err := env.userService.UserProfile(test.ctx, user.ID); !errors.Is(err, test.code) {
			t.Fatalf("profile=%v want=%s", err, test.code)
		}
		if _, err := env.userService.UpdateProfile(test.ctx, user.ID, &svc.UpdateUserRequest{Email: "new@example.test"}); !errors.Is(err, test.code) {
			t.Fatalf("update=%v want=%s", err, test.code)
		}
		if err := env.userService.ChangePassword(test.ctx, user.ID, &svc.ChangePasswordRequest{OldPassword: "oldpassword", NewPassword: "newpassword"}); !errors.Is(err, test.code) {
			t.Fatalf("password=%v want=%s", err, test.code)
		}
	}
	if _, err := env.userService.UpdateProfile(trusted, user.ID, nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("nil profile=%v", err)
	}
	if err := env.userService.ChangePassword(trusted, user.ID, nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("nil password=%v", err)
	}
	if _, err := env.userService.UserProfile(trusted, 0); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("zero ID=%v", err)
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("rejected calls accessed GORM reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestUserSelfProfileProjectsOnlyRealSameTenantAssociations(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := selfUserFixture(t, env)
	now := time.Now()
	for i, tenantID := range []string{env.tenantID, "other", env.tenantID} {
		group := &iamentity.Group{TenantID: tenantID, ManagedScopeID: env.rootScopeID + 100, OwnerID: "owner", Name: "group" + strconv.Itoa(i)}
		role := &iamentity.Role{TenantID: tenantID, NamespaceScopeID: env.rootScopeID + 100, OwnerID: "owner", Name: "role" + strconv.Itoa(i), Status: "inactive"}
		group.ID, role.ID = int64(100+i), int64(100+i)
		if i == 2 {
			group.DeletedAt, role.DeletedAt = &now, &now
		}
		for _, item := range []any{group, role, &iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: env.rootScopeID, Status: "inactive"}} {
			if err := env.db.Create(item).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, group.ID).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, ctx := range []context.Context{selfUserContext(t, env, "99", false), selfUserContext(t, env, "", true)} {
		profile, err := env.userService.UserProfile(ctx, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(profile.Groups) != 1 || profile.Groups[0].ID != 100 || len(profile.Roles) != 1 || profile.Roles[0].ID != 100 || profile.Roles[0].NamespaceScope != nil {
			t.Fatalf("profile changed disclosure or leaked associations: %+v", profile)
		}
	}
	// The existing profile display includes same-tenant associations outside the
	// caller's scope and inactive bindings; self writes keep their scope boundary.
	outside, err := scoped.WithDataScope(selfUserContext(t, env, "99", false), scoped.Filtered(env.rootScopeID+100))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UpdateProfile(outside, user.ID, &svc.UpdateUserRequest{Avatar: "forbidden"}); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("outside write=%v", err)
	}
	if err := env.userService.ChangePassword(outside, user.ID, &svc.ChangePasswordRequest{OldPassword: "oldpassword", NewPassword: "newpassword"}); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("outside password=%v", err)
	}
	if _, err := env.userService.UpdateProfile(selfUserContext(t, env, "", true), user.ID, &svc.UpdateUserRequest{Avatar: "system"}); err != nil {
		t.Fatalf("specified System target=%v", err)
	}
	other := &iamentity.User{TenantID: "other", ManagedScopeID: env.rootScopeID, Username: "other", Email: "other@example.test"}
	other.ID = 101
	if err := env.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UserProfile(selfUserContext(t, env, "", true), other.ID); !errors.Is(err, errors.NotFound) && !errors.Is(err, errors.Forbidden) {
		t.Fatalf("System cross-tenant profile=%v", err)
	}
}

func TestUserSelfProfileReturnsCompleteAssociatedSetWithOneTargetRead(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := selfUserFixture(t, env)
	groups, roles := make([]iamentity.Group, 1003), make([]iamentity.Role, 1003)
	bindings := make([]iamentity.UserRoleBinding, 1002)
	for i := range groups {
		groups[i] = iamentity.Group{TenantID: env.tenantID, ManagedScopeID: env.rootScopeID + 100, OwnerID: "owner", Name: "group" + strconv.Itoa(i)}
		roles[i] = iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: env.rootScopeID + 100, OwnerID: "owner", Name: "role" + strconv.Itoa(i)}
		groups[i].ID, roles[i].ID = int64(100+i), int64(100+i)
		if i < len(bindings) {
			bindings[i] = iamentity.UserRoleBinding{UserID: user.ID, RoleID: roles[i].ID, GrantScopeID: env.rootScopeID, Status: "inactive"}
		}
	}
	for _, items := range []any{&groups, &roles, &bindings} {
		if err := env.db.CreateInBatches(items, 200).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i := range bindings {
		if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, groups[i].ID).Error; err != nil {
			t.Fatal(err)
		}
	}
	var userReads atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("user-self:target-reads", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" {
			userReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	profile, err := env.userService.UserProfile(selfUserContext(t, env, "99", false), user.ID)
	if err != nil || len(profile.Groups) != 1002 || len(profile.Roles) != 1002 || userReads.Load() != 1 {
		t.Fatalf("complete profile groups=%d roles=%d targetReads=%d error=%v", len(profile.Groups), len(profile.Roles), userReads.Load(), err)
	}
}

func TestUserSelfEmailAndPasswordKeepValidationAndAtomicGuards(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := selfUserFixture(t, env)
	ctx := selfUserContext(t, env, "99", false)
	other := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: env.rootScopeID + 100, Username: "occupied", Email: "occupied@example.test"}
	other.ID = 100
	if err := env.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UpdateProfile(ctx, user.ID, &svc.UpdateUserRequest{Email: other.Email, Avatar: "must-rollback"}); !errors.Is(err, errors.Validation) {
		t.Fatalf("same-tenant out-of-scope email=%v", err)
	}
	for _, request := range []*svc.ChangePasswordRequest{{OldPassword: "wrong", NewPassword: "newpassword"}, {OldPassword: "oldpassword", NewPassword: "short"}} {
		if err := env.userService.ChangePassword(ctx, user.ID, request); !errors.Is(err, errors.Validation) {
			t.Fatalf("password validation=%v", err)
		}
	}
	changed, err := env.userService.UpdateProfile(ctx, user.ID, &svc.UpdateUserRequest{Email: "new@example.test", Avatar: "new-avatar"})
	if err != nil || changed.Email != "new@example.test" || changed.Avatar != "new-avatar" || changed.Version != user.Version+1 {
		t.Fatalf("profile update=%+v error=%v", changed, err)
	}
	if err := env.userService.ChangePassword(ctx, user.ID, &svc.ChangePasswordRequest{OldPassword: "oldpassword", NewPassword: "newpassword"}); err != nil {
		t.Fatal(err)
	}
	var stored iamentity.User
	if err := env.db.First(&stored, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(stored.Password), []byte("newpassword")) != nil || stored.Username != "self" || stored.ManagedScopeID != user.ManagedScopeID || stored.Email != "new@example.test" {
		t.Fatalf("password or protected fields changed incorrectly: %+v", &stored)
	}
	var once atomic.Bool
	if err := env.db.Callback().Query().After("gorm:query").Register("user-self:version-conflict", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" && once.CompareAndSwap(false, true) {
			if err := env.db.Exec("UPDATE users SET version = version + 1 WHERE id = ?", user.ID).Error; err != nil {
				t.Error(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UpdateProfile(ctx, user.ID, &svc.UpdateUserRequest{Avatar: "conflict"}); !errors.Is(err, errors.Concurrency) {
		t.Fatalf("frozen version conflict=%v", err)
	}
	if err := env.db.First(&stored, user.ID).Error; err != nil || stored.Avatar != "new-avatar" {
		t.Fatalf("conflict persisted update: %+v error=%v", &stored, err)
	}
}

func TestUserSelfHTTPUsesTrustedSubjectAndRejectsTraceBeforeSQL(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := selfUserFixture(t, env)
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	ctx := selfUserContext(t, env, strconv.FormatInt(user.ID, 10), false)
	// A tracing UserID may differ from the trusted principal.
	ctx, err = contextx.WithUserID(ctx, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path, body string }{{"GET", "/iam/users/me", ""},
		{"PUT", "/iam/users/me", `{"avatar":"http-avatar"}`},
		{"POST", "/iam/users/me/change-password", `{"old_password":"oldpassword","new_password":"http-password"}`}} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)).WithContext(ctx))
		if recorder.Code != 200 || strings.Contains(recorder.Body.String(), "password_hash") || strings.Contains(recorder.Body.String(), "$2a$") {
			t.Fatalf("%s status=%d body=%s", test.path, recorder.Code, recorder.Body.String())
		}
	}
	var reads atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("user-self-http:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(base, "99")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path string }{{"GET", "/iam/users/me"}, {"PUT", "/iam/users/me"}, {"POST", "/iam/users/me/change-password"}} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`)).WithContext(trace))
		if recorder.Code != 401 {
			t.Fatalf("trace %s status=%d body=%s", test.path, recorder.Code, recorder.Body.String())
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("tracing-only HTTP read %d queries", reads.Load())
	}
}
