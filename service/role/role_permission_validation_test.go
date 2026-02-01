package role

import (
	"testing"

	iammw "gochen-iam/middleware"
)

func TestIsValidPermission(t *testing.T) {
	valid := []string{
		"task:read",
		"task:write",
		"user:read_self",
		"story:admin",
		"mcp:invoke",
		"SYSTEM:READ",
		"a:b",
		"a1:b2",
		"a_b:c_d",
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
		"task:read:extra",
		"task:read-self",
		"task read",
		"task/read",
		"task:read\n",
	}
	for _, p := range invalid {
		if iammw.IsValidPermissionCode(p) {
			t.Fatalf("expected %q to be invalid", p)
		}
	}
}

func TestValidatePermissions_StrictRegistry(t *testing.T) {
	// 注册系统所需权限（模拟路由装配期调用 PermissionMiddleware）
	_ = iammw.PermissionMiddleware("role_permission_validation_test:read")

	s := &RoleService{}
	if err := s.validatePermissions([]string{"role_permission_validation_test:read"}); err != nil {
		t.Fatalf("expected permission in registry to pass, got: %v", err)
	}
	if err := s.validatePermissions([]string{"role_permission_validation_test:write"}); err == nil {
		t.Fatalf("expected unknown permission to fail")
	}
}
