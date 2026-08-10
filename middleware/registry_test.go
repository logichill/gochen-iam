package middleware

import "testing"

func TestHasRequiredPermissionDoesNotExpandRegisteredWildcard(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	RegisterRequiredPermissions(
		"api:registry_direction_test:read",
		"api:*:*",
	)

	if !HasRequiredPermission("api:registry_direction_test:*") {
		t.Fatal("candidate wildcard should match a registered concrete permission")
	}
	if HasRequiredPermission("api:registry_direction_test:write") {
		t.Fatal("registered wildcard must not make an unknown concrete permission valid")
	}
}
