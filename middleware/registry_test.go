package middleware

import "testing"

func TestHasRequiredPermissionDoesNotExpandRegisteredWildcard(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	RegisterRequiredPermissions(
		"registry_direction_test:api:read",
		"*:api:*",
	)

	if !HasRequiredPermission("registry_direction_test:api:*") {
		t.Fatal("candidate wildcard should match a registered concrete permission")
	}
	if HasRequiredPermission("registry_direction_test:api:write") {
		t.Fatal("registered wildcard must not make an unknown concrete permission valid")
	}
}
