package role

import (
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
)

func TestIsValidPermission(t *testing.T) {
	valid := []string{
		"task:api:read",
		"task:api:write",
		"task:api:*",
		"*:api:*",
		"*:*:*",
		"user:api:read_self",
		"story:api:admin",
		"mcp:action:invoke",
		"dashboard.home:menu:view",
		"*:menu:view",
		"SYSTEM:API:READ",
		"a1_b2:api:read_self",
		"a_b.c_d:menu:view",
	}
	for _, p := range valid {
		if !iammw.IsValidPermissionCode(p) {
			t.Fatalf("expected %q to be valid", p)
		}
	}

	invalid := []string{
		"",
		" ",
		"task",
		"task:",
		":read",
		"task:read",
		"task:read:extra:value",
		"mcp:action-invoke",
		"task read",
		"task/read",
		"task:api:read\n",
	}
	for _, p := range invalid {
		if iammw.IsValidPermissionCode(p) {
			t.Fatalf("expected %q to be invalid", p)
		}
	}
}

func TestValidatePermissions_StrictRegistry(t *testing.T) {
	// 注册系统所需权限（模拟路由装配期调用 PermissionMiddleware）
	_ = iammw.PermissionMiddleware(iammw.PermissionCode("role_permission_validation_test:api:read"))
	_ = iammw.PermissionMiddleware(iammw.PermissionCode("role_permission_validation_test:menu:view"))

	s := &RoleService{}
	if err := s.validatePermissions([]string{"role_permission_validation_test:api:read"}); err != nil {
		t.Fatalf("expected permission in registry to pass, got: %v", err)
	}
	if err := s.validatePermissions([]string{"*:api:*", "*:menu:view"}); err != nil {
		t.Fatalf("expected wildcard permissions matched by registry to pass, got: %v", err)
	}
	if err := s.validatePermissions([]string{"*:*:*"}); err != nil {
		t.Fatalf("expected full wildcard permission to pass when registry is non-empty, got: %v", err)
	}
	if err := s.validatePermissions([]string{"role_permission_validation_test:api:write"}); err == nil {
		t.Fatalf("expected unknown permission to fail")
	}
	if err := s.validatePermissions([]string{"role_permission_validation_test:action:write"}); err == nil {
		t.Fatalf("expected unknown action permission to fail")
	}
}

func TestValidatePermissionsForScope_RejectsBuiltinWildcardPermissions(t *testing.T) {
	// 走生产注册路径：目录一旦不再被登记，本用例会直接失败。
	svc.RegisterIAMPermissionCatalog()

	s := &RoleService{}
	scope := &iamentity.Scope{Type: iamentity.ScopeTypeTenant}

	for _, permission := range []string{"*:menu:view", "*:api:*", "*:*:*"} {
		if err := s.validatePermissionsForScope([]string{permission}, scope); err == nil {
			t.Fatalf("expected builtin-only permission %q to fail for custom role", permission)
		}
	}
}
