package group_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	"gochen-iam/router"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func associationPrincipal(t *testing.T, tenantID, subject, kind string, permissions ...string) context.Context {
	t.Helper()
	ctx, err := contextx.WithTenantID(t.Context(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: subject, ActiveScopeID: 1, Permissions: permissions})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, kind)
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func countAssociationAccess(t *testing.T, storage *gorm.DB) (reads, writes *atomic.Int64) {
	t.Helper()
	reads, writes = &atomic.Int64{}, &atomic.Int64{}
	if err := storage.Callback().Query().Before("gorm:query").Register("group:test:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		storage.Callback().Create().Before("gorm:create").Register("group:test:writes", func(*gorm.DB) { writes.Add(1) }),
		storage.Callback().Update().Before("gorm:update").Register("group:test:writes", func(*gorm.DB) { writes.Add(1) }),
		storage.Callback().Delete().Before("gorm:delete").Register("group:test:writes", func(*gorm.DB) { writes.Add(1) }),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return reads, writes
}

func createAssociationGroup(t *testing.T, env *groupServiceTestEnv) *iamentity.Group {
	t.Helper()
	group, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "association"})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestGroupAssociationConstructionRequiresActualProviders(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	for _, providers := range []struct {
		group      *grouprepo.GroupRepo
		user       *userrepo.UserRepo
		role       *rolerepo.RoleRepo
		authorizer *svc.IAMAccess
	}{
		{nil, env.userRepo, env.roleRepo, svc.NewIAMAccess(nil)},
		{&grouprepo.GroupRepo{}, env.userRepo, env.roleRepo, svc.NewIAMAccess(nil)},
		{env.groupRepo, nil, env.roleRepo, svc.NewIAMAccess(nil)},
		{env.groupRepo, env.userRepo, &rolerepo.RoleRepo{}, svc.NewIAMAccess(nil)},
		{env.groupRepo, env.userRepo, env.roleRepo, nil},
	} {
		if _, err := groupsvc.NewGroupService(providers.group, providers.user, providers.role, nil, providers.authorizer, nil); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("missing provider error=%v", err)
		}
	}
}

func TestGroupAssociationRejectsUntrustedAndUnpermittedBeforeReading(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	trace, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err = contextx.WithUserID(trace, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), trace, associationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")} {
		for _, invoke := range []func(context.Context) error{
			func(ctx context.Context) error { return env.groupService.AddUserToGroup(ctx, 1, 1) },
			func(ctx context.Context) error { return env.groupService.RemoveUserFromGroup(ctx, 1, 1) },
			func(ctx context.Context) error { return env.groupService.AddGroupRole(ctx, 1, 1) },
			func(ctx context.Context) error { return env.groupService.RemoveGroupRole(ctx, 1, 1) },
		} {
			if err := invoke(ctx); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("unpermitted error=%v", err)
			}
		}
		batch, err := env.groupService.BulkAddUsersToGroup(ctx, 1, []int64{1, 2})
		if err != nil || batch == nil || batch.FailureCount != 2 || batch.SuccessCount != 0 || len(batch.Errors) != 2 {
			t.Fatalf("batch permission response=%+v error=%v", batch, err)
		}
		for _, failure := range batch.Errors {
			if !errors.Is(failure, errors.Forbidden) {
				t.Fatalf("batch permission failure=%v", failure)
			}
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupAssociationHTTPChecksEntryBeforeTenantFacts(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{
		{associationPrincipal(t, env.tenantID, "7", "tenant", "group:api:write"), errors.Forbidden},
		{associationPrincipal(t, env.tenantID, "7", "family", "group:api:write", "group:api:manage"), errors.Forbidden},
		{associationPrincipal(t, env.tenantID, "service", "platform", "group:api:write", "group:api:manage"), errors.Unauthorized},
	} {
		for _, action := range []string{"add_user", "remove_user", "add_role", "remove_role"} {
			if _, err := env.groupService.ExecuteAssociationHTTP(test.ctx, action, groupsvc.GroupAssociationInput{ID: 1, RelatedIDs: []int64{1}}); !errors.Is(err, test.code) {
				t.Fatalf("HTTP entry %s error=%v", action, err)
			}
		}
		result, err := env.groupService.ExecuteAssociationHTTP(test.ctx, "bulk_add_users", groupsvc.GroupAssociationInput{ID: 1, RelatedIDs: []int64{1}})
		if err != nil || result == nil || result.FailureCount != 1 || result.SuccessCount != 0 {
			t.Fatalf("HTTP batch entry result=%+v error=%v", result, err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("entry denial reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupAssociationPrechecksEveryTargetAndFreezesOwnership(t *testing.T) {
	for _, change := range []string{"user_scope", "role_scope", "tenant", "deleted", "group_scope"} {
		t.Run(change, func(t *testing.T) {
			env := setupGroupServiceTest(t)
			defer env.teardown(t)
			group := createAssociationGroup(t, env)
			user := env.createTestUser(t, "target", "target@example.com")
			role := env.createTestRole(t, "target-role")
			ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
			var err error
			switch change {
			case "user_scope":
				err = env.db.Model(user).Update("managed_scope_id", 2).Error
			case "role_scope":
				err = env.db.Model(role).Update("namespace_scope_id", 2).Error
			case "tenant":
				err = env.db.Model(user).Update("tenant_id", "other").Error
			case "deleted":
				err = env.db.Model(user).Update("deleted_at", "2026-11-05 00:00:00").Error
			case "group_scope":
				err = env.db.Model(group).Update("managed_scope_id", 2).Error
			}
			if err != nil {
				t.Fatal(err)
			}
			_, writes := countAssociationAccess(t, env.db)
			if change == "role_scope" {
				err = env.groupService.AddGroupRole(ctx, group.GetID(), role.GetID())
			} else {
				err = env.groupService.AddUserToGroup(ctx, group.GetID(), user.GetID())
			}
			if err == nil || writes.Load() != 0 {
				t.Fatalf("unavailable target error=%v writes=%d", err, writes.Load())
			}
		})
	}
}

func TestGroupAssociationBulkRejectsInvalidBatchBeforeFirstWrite(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	u := env.createTestUser(t, "valid", "valid@example.com")
	_, writes := countAssociationAccess(t, env.db)
	result, err := env.groupService.BulkAddUsersToGroup(env.backgroundCtx, group.GetID(), []int64{u.GetID(), -1, u.GetID()})
	if err != nil || result == nil || result.SuccessCount != 0 || result.FailureCount != 1 || len(result.Errors) != 1 || writes.Load() != 0 {
		t.Fatalf("invalid batch result=%+v error=%v writes=%d", result, err, writes.Load())
	}
}

func TestGroupAssociationBulkRollsBackDatabaseFailure(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	u1 := env.createTestUser(t, "first", "first@example.com")
	u2 := env.createTestUser(t, "second", "second@example.com")
	trigger := fmt.Sprintf("CREATE TRIGGER reject_second_association BEFORE INSERT ON user_groups WHEN NEW.user_id = %d BEGIN SELECT RAISE(ABORT, 'association rejected'); END", u2.GetID())
	if err := env.db.Exec(trigger).Error; err != nil {
		t.Fatal(err)
	}
	result, err := env.groupService.BulkAddUsersToGroup(env.backgroundCtx, group.GetID(), []int64{u1.GetID(), u2.GetID()})
	if err != nil || result == nil || result.SuccessCount != 0 || result.FailureCount != 1 || len(result.Errors) != 1 {
		t.Fatalf("database failure result=%+v error=%v", result, err)
	}
	var count int64
	if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rollback associations=%d error=%v", count, err)
	}
}

func TestGroupAssociationRechecksOwnershipAndVersionInTransaction(t *testing.T) {
	for _, change := range []string{"related_version", "related_scope", "group_scope"} {
		t.Run(change, func(t *testing.T) {
			env := setupGroupServiceTest(t)
			defer env.teardown(t)
			group := createAssociationGroup(t, env)
			u := env.createTestUser(t, "changing", "changing@example.com")
			reads := &atomic.Int64{}
			if err := env.db.Callback().Query().Before("gorm:query").Register("group:test:change-after-precheck", func(tx *gorm.DB) {
				if tx.Statement.Table != "users" || reads.Add(1) != 2 {
					return
				}
				mutation := tx.Session(&gorm.Session{NewDB: true, SkipHooks: true})
				var err error
				switch change {
				case "related_version":
					err = mutation.Table("users").Where("id = ?", u.GetID()).UpdateColumn("version", gorm.Expr("version + 1")).Error
				case "related_scope":
					err = mutation.Table("users").Where("id = ?", u.GetID()).UpdateColumn("managed_scope_id", 2).Error
				case "group_scope":
					err = mutation.Table("groups").Where("id = ?", group.GetID()).UpdateColumn("managed_scope_id", 2).Error
				}
				if err != nil {
					tx.AddError(err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
			if err := env.groupService.AddUserToGroup(ctx, group.GetID(), u.GetID()); err == nil {
				t.Fatal("changed ownership/version accepted")
			}
			if reads.Load() < 2 {
				t.Fatal("target was not rechecked inside the write transaction")
			}
			var count int64
			if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("changed target associations=%d error=%v", count, err)
			}
			persisted, err := env.userRepo.Repo.Get(env.backgroundCtx, u.GetID(), spec.All())
			if err != nil || persisted.GetVersion() != u.GetVersion() || persisted.ManagedScopeID != u.ManagedScopeID {
				t.Fatalf("related mutation escaped rollback: user=%+v error=%v", persisted, err)
			}
			persistedGroup, err := env.groupRepo.Get(env.backgroundCtx, group.GetID(), spec.All())
			if err != nil || persistedGroup.ManagedScopeID != group.ManagedScopeID {
				t.Fatalf("group mutation escaped rollback: group=%+v error=%v", persistedGroup, err)
			}
		})
	}
}

func TestGroupAssociationAllowsGroupDerivedUserAndRoleAccessWithoutHydration(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	u := env.createTestUser(t, "valid", "valid@example.com")
	r := env.createTestRole(t, "valid-role")
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	if err := env.db.Callback().Query().Before("gorm:query").Register("group:test:no-hydration", func(tx *gorm.DB) {
		if tx.Statement.Table == "scopes" || tx.Statement.Table == "user_role_bindings" || tx.Statement.Table == "scope_visibility_map" {
			tx.AddError(fmt.Errorf("unexpected undeclared hydration: %s", tx.Statement.Table))
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, invoke := range []func() error{
		func() error { return env.groupService.AddUserToGroup(ctx, group.GetID(), u.GetID()) },
		func() error { return env.groupService.AddGroupRole(ctx, group.GetID(), r.GetID()) },
		func() error { return env.groupService.RemoveUserFromGroup(ctx, group.GetID(), u.GetID()) },
		func() error { return env.groupService.RemoveGroupRole(ctx, group.GetID(), r.GetID()) },
	} {
		if err := invoke(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGroupAssociationActualHTTPLifecycle(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	u := env.createTestUser(t, "http", "http@example.com")
	r := env.createTestRole(t, "http-role")
	routes, err := router.NewGroupRoutes(env.groupService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	request := func(ctx context.Context, method, path, body string, status int) string {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(method, fmt.Sprintf("/iam/groups/%d%s", group.GetID(), path), strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != status {
			t.Fatalf("%s %s status=%d body=%s", method, path, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.String()
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:manage", "group:api:write")
	request(ctx, "POST", "/users", fmt.Sprintf(`{"user_id":%d}`, u.GetID()), http.StatusOK)
	request(ctx, "DELETE", fmt.Sprintf("/users/%d", u.GetID()), "", http.StatusOK)
	request(ctx, "POST", "/roles", fmt.Sprintf(`{"role_id":%d}`, r.GetID()), http.StatusOK)
	request(ctx, "DELETE", fmt.Sprintf("/roles/%d", r.GetID()), "", http.StatusOK)
	body := request(ctx, "POST", "/users/bulk", fmt.Sprintf(`{"user_ids":[%d,-1]}`, u.GetID()), http.StatusOK)
	if !strings.Contains(body, `"success_count":0`) || !strings.Contains(body, `"failure_count":1`) {
		t.Fatalf("bulk response=%s", body)
	}
	var count int64
	if err := env.db.Table("user_groups").Where("group_id = ?", group.GetID()).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("bulk rollback count=%d error=%v", count, err)
	}
	request(ctx, "POST", "/users/bulk", fmt.Sprintf(`{"user_ids":[%d]}`, u.GetID()), http.StatusOK)
	groupOnly := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	request(groupOnly, "POST", "/users", fmt.Sprintf(`{"user_id":%d}`, u.GetID()), http.StatusForbidden)
	manageOnly := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:manage")
	request(manageOnly, "POST", "/users", fmt.Sprintf(`{"user_id":%d}`, u.GetID()), http.StatusForbidden)
	body = request(manageOnly, "POST", "/users/bulk", fmt.Sprintf(`{"user_ids":[%d]}`, u.GetID()), http.StatusOK)
	if !strings.Contains(body, `"success_count":0`) || !strings.Contains(body, `"failure_count":1`) {
		t.Fatalf("batch permission response=%s", body)
	}
	request(t.Context(), "POST", "/users", fmt.Sprintf(`{"user_id":%d}`, u.GetID()), http.StatusUnauthorized)
	readContext := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:manage", "group:api:read")
	for _, test := range []struct {
		ctx    context.Context
		status int
	}{{ctx, http.StatusForbidden}, {readContext, http.StatusOK}} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/iam/groups/statistics", nil).WithContext(test.ctx))
		if recorder.Code != test.status {
			t.Fatalf("statistics HTTP status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if test.status == http.StatusOK && (!strings.Contains(recorder.Body.String(), `"total_groups":1`) || !strings.Contains(recorder.Body.String(), `"total_roles":1`)) {
			t.Fatalf("statistics HTTP body=%s", recorder.Body.String())
		}
	}
	if _, err := env.groupRepo.Get(env.backgroundCtx, group.GetID(), spec.All()); err != nil {
		t.Fatal(err)
	}
}
