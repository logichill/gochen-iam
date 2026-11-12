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
	iamtenant "gochen-iam/tenant"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserGroupRepositoryUsesBothConditionsInTransaction(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 2, OwnerID: "owner", Name: "target"}
	group.ID = 100
	for _, item := range []any{user, group} {
		if err := env.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	userCondition := spec.And(spec.Eq(meta.ID(), user.ID), spec.Eq(meta.ByDimension("scope"), int64(1)))
	groupCondition := spec.And(spec.Eq(meta.ID(), group.ID), spec.Eq(meta.ByDimension("scope"), int64(2)))
	if err := env.userRepo.AssignToGroup(env.backgroundCtx, user.ID, group.ID, userCondition, groupCondition); err != nil {
		t.Fatal(err)
	}
	if err := env.userRepo.AssignToGroup(env.backgroundCtx, user.ID, group.ID, userCondition, groupCondition); err != nil {
		t.Fatalf("duplicate assignment lost idempotency=%v", err)
	}
	if err := env.userRepo.RemoveFromGroup(env.backgroundCtx, user.ID, group.ID, userCondition, userCondition); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("group did not execute its independent condition=%v", err)
	}
	var count int64
	if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("denied removal changed link=%d error=%v", count, err)
	}
	if err := env.userRepo.RemoveFromGroup(env.backgroundCtx, user.ID, group.ID, userCondition, groupCondition); err != nil {
		t.Fatal(err)
	}
	if err := env.userRepo.RemoveFromGroup(env.backgroundCtx, user.ID, group.ID, userCondition, groupCondition); err != nil {
		t.Fatalf("duplicate removal lost idempotency=%v", err)
	}
	if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("removal link=%d error=%v", count, err)
	}
}

func TestUserGroupWritesOnRealHTTP(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: "owner", Name: "target"}
	group.ID = 100
	for _, item := range []any{user, group} {
		if err := env.db.Create(item).Error; err != nil {
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
	for _, test := range []struct {
		method, path, body string
		count              int64
	}{
		{"POST", "/iam/users/99/groups", `{"group_id":100}`, 1},
		{"DELETE", "/iam/users/99/groups/100", "", 0},
	} {
		for _, permitted := range []bool{false, true} {
			permissions := []string{"user:api:manage", "user:api:read"}
			if permitted {
				permissions = append(permissions, "user:api:write")
			}
			ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", permissions...)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)).WithContext(ctx)
			request.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(recorder, request)
			if permitted {
				if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"user_id":99`) || !strings.Contains(recorder.Body.String(), `"group_id":100`) {
					t.Fatalf("actual %s status=%d body=%s", test.method, recorder.Code, recorder.Body.String())
				}
				var count int64
				if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != test.count {
					t.Fatalf("HTTP link=%d error=%v", count, err)
				}
			} else if recorder.Code != 403 {
				t.Fatalf("actual denial status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		}
	}
}

func TestUserGroupWritesRejectBeforeResourceAccess(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	reads, writes := &atomic.Int64{}, &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:group:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Create().Before("gorm:create").Register("user:group:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
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
	for _, ctx := range []context.Context{t.Context(), trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")} {
		for _, invoke := range []func(context.Context, int64, int64) error{env.userService.AssignToGroup, env.userService.RemoveFromGroup} {
			if err := invoke(ctx, 99, 100); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("ordinary denial=%v", err)
			}
		}
		result, err := env.userService.BulkAssignToGroup(ctx, 100, []int64{98, 99})
		if err != nil || result.SuccessCount != 0 || result.FailureCount != 2 || len(result.Errors) != 2 {
			t.Fatalf("batch denial=%+v error=%v", result, err)
		}
	}
	for _, action := range []string{"assign_group", "remove_group"} {
		for _, test := range []struct {
			ctx  context.Context
			code errors.ErrorCode
		}{
			{nil, errors.InvalidInput},
			{userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "trace", "tenant", "user:api:write", "user:api:manage"), errors.Unauthorized},
		} {
			if err := env.userService.ExecuteGroupWriteHTTP(test.ctx, action, usersvc.UserGroupWriteInput{UserID: 99, GroupID: 100}); !errors.Is(err, test.code) {
				t.Fatalf("HTTP %s=%v, want %s", action, err, test.code)
			}
		}
		if err := env.userService.ExecuteGroupWriteHTTP(trace, action, usersvc.UserGroupWriteInput{UserID: 99}); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("invalid group ID=%v", err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestUserGroupWritesPreserveScopeAndPartialBatch(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	hidden := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 2, HomeTenantID: env.tenantID, HomeScopeID: 2, OwnerID: "owner", Username: "hidden", Email: "hidden@example.test"}
	hidden.ID = 98
	group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: "owner", Name: "target"}
	group.ID = 100
	for _, item := range []any{user, hidden, group} {
		if err := env.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write", "user:api:manage")
	result, err := env.userService.BulkAssignToGroup(ctx, group.ID, []int64{user.ID, hidden.ID, 999})
	if err != nil || result.SuccessCount != 1 || result.FailureCount != 2 || !errors.Is(result.Errors[0], errors.Forbidden) || !errors.Is(result.Errors[1], errors.NotFound) {
		t.Fatalf("batch response=%+v error=%v", result, err)
	}
	var count int64
	if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("partial batch associations=%d error=%v", count, err)
	}
	if err := env.userService.ExecuteGroupWriteHTTP(ctx, "remove_group", usersvc.UserGroupWriteInput{UserID: user.ID, GroupID: group.ID}); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(group).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	for _, invoke := range []func(context.Context, int64, int64) error{env.userService.AssignToGroup, env.userService.RemoveFromGroup} {
		if err := invoke(ctx, user.ID, group.ID); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("outside group scope=%v", err)
		}
	}
	single := iamtenant.WithPolicy(userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
	if err := env.userService.ExecuteGroupWriteHTTP(single, "assign_group", usersvc.UserGroupWriteInput{UserID: user.ID, GroupID: group.ID}); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("single lost data condition=%v", err)
	}
	if err := env.userService.AssignToGroup(env.backgroundCtx, user.ID, group.ID); err != nil {
		t.Fatalf("System assignment=%v", err)
	}
}

func TestUserGroupWritesFreezeBothResources(t *testing.T) {
	for _, table := range []string{"users", "groups"} {
		t.Run(table, func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
			user.ID = 99
			group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: "owner", Name: "target"}
			group.ID = 100
			for _, item := range []any{user, group} {
				if err := env.db.Create(item).Error; err != nil {
					t.Fatal(err)
				}
			}
			injected := &atomic.Bool{}
			if err := env.db.Callback().Query().After("gorm:query").Register("user:group:conflict", func(tx *gorm.DB) {
				if tx.Statement.Table == table && injected.CompareAndSwap(false, true) {
					if err := env.db.Table(table).Where("id IN ?", []int64{99, 100}).UpdateColumn("version", gorm.Expr("version + 1")).Error; err != nil {
						tx.AddError(err)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")
			err := env.userService.AssignToGroup(ctx, user.ID, group.ID)
			code := errors.Conflict
			if !injected.Load() || !errors.Is(err, code) {
				t.Fatalf("stale %s association=%v, want %s", table, err, code)
			}
			var count int64
			if err := env.db.Table("user_groups").Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("stale target wrote associations=%d error=%v", count, err)
			}
		})
	}
}
