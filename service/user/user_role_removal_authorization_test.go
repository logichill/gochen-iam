package user_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-iam/router"
	usersvc "gochen-iam/service/user"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserRoleRemovalRejectsBeforeResourceAccess(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: 1, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	reads, writes := &atomic.Int64{}, &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:removal:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Delete().Before("gorm:delete").Register("user:removal:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err = contextx.WithUserID(trace, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		if err := env.userService.RemoveRole(ctx, user.ID, role.ID); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("ordinary denial=%v", err)
		}
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{
		{nil, errors.InvalidInput},
		{userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "trace", "tenant", "user:api:write", "user:api:manage"), errors.Unauthorized},
	} {
		if err := env.userService.ExecuteRoleRemovalHTTP(test.ctx, usersvc.UserRoleRemovalInput{UserID: user.ID, RoleID: role.ID}); !errors.Is(err, test.code) {
			t.Fatalf("HTTP denial=%v, want %s", err, test.code)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied reads=%d writes=%d", reads.Load(), writes.Load())
	}
	if err := env.userService.RemoveRole(env.backgroundCtx, user.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatal("actual repository observers did not see permitted execution")
	}
}

func TestUserRoleRemovalRepositoryKeepsSeparateConditionsAndAllBindings(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	if err := env.db.Model(role).UpdateColumn("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	for _, binding := range []*iamentity.UserRoleBinding{
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: 1, Status: "active"},
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: 999, Status: "inactive"},
		{UserID: user.ID, RoleID: role.ID + 1, GrantScopeID: 1, Status: "active"},
		{UserID: user.ID + 1, RoleID: role.ID, GrantScopeID: 1, Status: "active"},
	} {
		if err := env.db.Create(binding).Error; err != nil {
			t.Fatal(err)
		}
	}
	userCondition := spec.Eq(meta.ByDimension("scope"), int64(1))
	roleCondition := spec.Eq(meta.ByDimension("scope"), int64(2))
	if err := env.userRepo.RemoveRole(env.backgroundCtx, user.ID, role.ID, userCondition, userCondition); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("role condition ignored=%v", err)
	}
	var count int64
	if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 4 {
		t.Fatalf("denied removal count=%d error=%v", count, err)
	}
	if err := env.userRepo.RemoveRole(env.backgroundCtx, user.ID, role.ID, userCondition, roleCondition); err != nil {
		t.Fatal(err)
	}
	if err := env.userRepo.RemoveRole(env.backgroundCtx, user.ID, role.ID, userCondition, roleCondition); err != nil {
		t.Fatalf("repeat removal=%v", err)
	}
	if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("all trusted bindings removal count=%d error=%v", count, err)
	}
}

func TestUserRoleRemovalFreezesUserAndRoleBeforeDeletion(t *testing.T) {
	for _, table := range []string{"users", "roles"} {
		t.Run(table, func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user, role := roleAssignmentTargets(t, env)
			if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: 1, Status: "active"}).Error; err != nil {
				t.Fatal(err)
			}
			injected := &atomic.Bool{}
			if err := env.db.Callback().Query().After("gorm:query").Register("user:removal:change", func(tx *gorm.DB) {
				if tx.Statement.Table == table && injected.CompareAndSwap(false, true) {
					if err := env.db.Table(table).Where("id IN ?", []int64{user.ID, role.ID}).UpdateColumn("version", gorm.Expr("version + 1")).Error; err != nil {
						tx.AddError(err)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := env.userService.RemoveRole(env.backgroundCtx, user.ID, role.ID); !errors.Is(err, errors.Conflict) || !injected.Load() {
				t.Fatalf("stale %s removal=%v", table, err)
			}
			var count int64
			if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("stale deletion count=%d error=%v", count, err)
			}
		})
	}
}

func TestUserRoleRemovalOnRealHTTP(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	for _, grant := range []int64{1, 999} {
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: grant, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, permitted := range []bool{false, true} {
		permissions := []string{"user:api:manage", "user:api:read"}
		if permitted {
			permissions = append(permissions, "user:api:write")
		}
		ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", permissions...)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest("DELETE", "/iam/users/99/roles/100", nil).WithContext(ctx))
		if permitted {
			if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"role_id":100`) {
				t.Fatalf("HTTP status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		} else if recorder.Code != 403 {
			t.Fatalf("denied HTTP status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var count int64
		want := int64(2)
		if permitted {
			want = 0
		}
		if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != want {
			t.Fatalf("HTTP count=%d want=%d error=%v", count, want, err)
		}
	}
}
