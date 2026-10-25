package role

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	auth "gochen-runtime/host/authz"
	"gochen/contextx"
	"gochen/errors"
)

// assertCreateRoleDoesNotPanic 把 CreateRole 的 panic（R3b-F08 的原始失败模式）
// 显式呈现为断言失败，而不是仅依赖测试框架的崩溃栈。
func assertCreateRoleDoesNotPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CreateRole panicked with scopeAuthorizer == nil (R3b-F08 regression): %v", r)
		}
	}()
	fn()
}

// TestRoleServiceCreateRole_NilScopeAuthorizerFallsBackToManagedScope 回归 R3b-F08：
// scopeAuthorizer == nil 时 resolveTenantScope 返回 (nil, nil)，CreateRole 曾无条件
// 解引用 namespaceScope.ID 触发 panic。修复后在上下文包含完整 scope 事实（ID 与 kind）时
// 与 governance 一致回退到上下文 managed scope 并完成创建。
func TestRoleServiceCreateRole_NilScopeAuthorizerFallsBackToManagedScope(t *testing.T) {
	svc.RegisterIAMPermissionCatalog()

	env := setupRoleBatchTest(t)
	defer env.teardown(t)

	ctx := iamauth.BindActiveScopeContext(env.backgroundCtx, 1, "tenant")
	var created *iamentity.Role
	assertCreateRoleDoesNotPanic(t, func() {
		role, err := env.roleService.CreateRole(ctx, &svc.CreateRoleRequest{
			TenantID:    env.tenantID,
			Name:        "r3bf08-fallback-role",
			Description: "nil scopeAuthorizer 回退到上下文 managed scope",
			Permissions: []string{svc.RolePermissionSet.Code(iammw.ActionWrite)},
		})
		if err != nil {
			t.Fatalf("CreateRole with nil scopeAuthorizer: expected fallback success, got %v", err)
		}
		created = role
	})

	if created == nil {
		t.Fatalf("expected created role, got nil")
	}
	if created.NamespaceScopeID != 1 {
		t.Fatalf("expected fallback namespace scope 1 from context, got %d", created.NamespaceScopeID)
	}

	persisted, err := env.roleRepo.Get(ctx, created.GetID())
	if err != nil {
		t.Fatalf("load persisted role: %v", err)
	}
	if persisted.NamespaceScopeID != 1 {
		t.Fatalf("expected persisted namespace scope 1, got %d", persisted.NamespaceScopeID)
	}
}

// TestRoleServiceCreateRole_NilScopeAuthorizerRejectsMissingScopeKind 回归 P1-1：
// nil scopeAuthorizer 且上下文仅有 managed scope ID 但缺少 scope kind 事实时，
// 必须 fail-closed 返回 InvalidInput，防止逃逸作用域校验。
func TestRoleServiceCreateRole_NilScopeAuthorizerRejectsMissingScopeKind(t *testing.T) {
	svc.RegisterIAMPermissionCatalog()

	env := setupRoleBatchTest(t)
	defer env.teardown(t)

	assertCreateRoleDoesNotPanic(t, func() {
		_, err := env.roleService.CreateRole(env.backgroundCtx, &svc.CreateRoleRequest{
			TenantID:    env.tenantID,
			Name:        "r3bf08-missing-kind-role",
			Description: "nil scopeAuthorizer 且缺少 scope kind 事实",
			Permissions: []string{svc.RolePermissionSet.Code(iammw.ActionWrite)},
		})
		if err == nil {
			t.Fatalf("expected InvalidInput when scope kind is missing")
		}
		if !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("expected InvalidInput, got %v", err)
		}
	})
}

// TestRoleServiceCreateRole_NilScopeAuthorizerRejectsMissingManagedScope 回归 R3b-F08：
// nil scopeAuthorizer 且上下文没有任何 managed scope 事实时，CreateRole 必须返回
// InvalidInput（与 governance 同源错误码），而不是 panic。
func TestRoleServiceCreateRole_NilScopeAuthorizerRejectsMissingManagedScope(t *testing.T) {
	svc.RegisterIAMPermissionCatalog()

	env := setupRoleBatchTest(t)
	defer env.teardown(t)

	ctx := context.Background()
	var err error
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:   1,
		Permissions: []string{"*:*:*"},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, env.tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	assertCreateRoleDoesNotPanic(t, func() {
		_, err := env.roleService.CreateRole(ctx, &svc.CreateRoleRequest{
			TenantID:    env.tenantID,
			Name:        "r3bf08-missing-scope-role",
			Description: "nil scopeAuthorizer 且上下文无 managed scope",
			Permissions: []string{svc.RolePermissionSet.Code(iammw.ActionWrite)},
		})
		if err == nil {
			t.Fatalf("expected InvalidInput when no managed scope is available")
		}
		if !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("expected InvalidInput, got %v", err)
		}
	})
}
