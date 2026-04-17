package role

import (
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
)

func TestIsValidPermission(t *testing.T) {
	valid := []string{
		"api:task:read",
		"api:task:write",
		"api:task:*",
		"api:*:*",
		"*:*:*",
		"api:user:read_self",
		"api:story:admin",
		"action:mcp:invoke",
		"menu:dashboard.home:view",
		"menu:*:view",
		"API:SYSTEM:READ",
		"api:a1_b2:read_self",
		"menu:a_b.c_d:view",
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
		"action:mcp-invoke",
		"task read",
		"task/read",
		"api:task:read\n",
	}
	for _, p := range invalid {
		if iammw.IsValidPermissionCode(p) {
			t.Fatalf("expected %q to be invalid", p)
		}
	}
}

func TestValidatePermissions_StrictRegistry(t *testing.T) {
	// 注册系统所需权限（模拟路由装配期调用 PermissionMiddleware）
	_ = iammw.PermissionMiddleware("api:role_permission_validation_test:read")
	_ = iammw.PermissionMiddleware("menu:role_permission_validation_test:view")

	s := &RoleService{}
	if err := s.validatePermissions([]string{"api:role_permission_validation_test:read"}); err != nil {
		t.Fatalf("expected permission in registry to pass, got: %v", err)
	}
	if err := s.validatePermissions([]string{"api:*:*", "menu:*:view"}); err != nil {
		t.Fatalf("expected wildcard permissions matched by registry to pass, got: %v", err)
	}
	if err := s.validatePermissions([]string{"*:*:*"}); err != nil {
		t.Fatalf("expected full wildcard permission to pass when registry is non-empty, got: %v", err)
	}
	if err := s.validatePermissions([]string{"api:role_permission_validation_test:write"}); err == nil {
		t.Fatalf("expected unknown permission to fail")
	}
	if err := s.validatePermissions([]string{"action:*:*"}); err == nil {
		t.Fatalf("expected unknown wildcard domain to fail")
	}
}

func TestValidatePermissionsForScope_RejectsBuiltinWildcardPermissions(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	s := &RoleService{}
	scope := &iamentity.Scope{Type: iamentity.ScopeTypeTenant}

	for _, permission := range []string{"menu:*:view", "api:*:*", "*:*:*"} {
		if err := s.validatePermissionsForScope([]string{permission}, scope); err == nil {
			t.Fatalf("expected builtin-only permission %q to fail for custom role", permission)
		}
	}
}
