package service

import (
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
)

func TestRoleHasAdminCapabilityMatchesWildcardPermission(t *testing.T) {
	role := &iamentity.Role{
		Status:      RoleStatusActive,
		Permissions: iamentity.PermissionArray{iammw.PermissionCode("*:*:*").Code},
	}
	if !roleHasAdminCapability(role) {
		t.Fatalf("expected wildcard permission to mark role as admin capable")
	}

	role.Status = RoleStatusInactive
	if roleHasAdminCapability(role) {
		t.Fatalf("expected inactive role not to be treated as admin capable")
	}
}

func TestAdminNamespaceScopesOnlyIncludesAdminCapableRoles(t *testing.T) {
	roles := []*iamentity.Role{
		{
			Status:           RoleStatusActive,
			NamespaceScopeID: 11,
			Permissions:      iamentity.PermissionArray{iammw.PermissionCode("*:*:*").Code},
		},
		{
			Status:           RoleStatusActive,
			NamespaceScopeID: 22,
			Permissions:      iamentity.PermissionArray{iammw.PermissionCode("user:api:read").Code},
		},
	}

	scopes := adminNamespaceScopes(roles)
	if len(scopes) != 1 {
		t.Fatalf("expected only admin-capable scopes to be protected, got %v", scopes)
	}
	if _, ok := scopes[11]; !ok {
		t.Fatalf("expected namespace scope 11 to be protected, got %v", scopes)
	}
	if _, ok := scopes[22]; ok {
		t.Fatalf("expected non-admin namespace scope 22 to be ignored, got %v", scopes)
	}
}

func TestRoleMatchesProtectedAdminScopeRequiresSameNamespace(t *testing.T) {
	protected := map[int64]struct{}{11: {}}
	matchingRole := &iamentity.Role{
		Status:           RoleStatusActive,
		NamespaceScopeID: 11,
		Permissions:      iamentity.PermissionArray{iammw.PermissionCode("*:*:*").Code},
	}
	if !roleMatchesProtectedAdminScope(matchingRole, protected) {
		t.Fatalf("expected admin role in protected namespace to match")
	}

	otherScopeRole := &iamentity.Role{
		Status:           RoleStatusActive,
		NamespaceScopeID: 22,
		Permissions:      iamentity.PermissionArray{iammw.PermissionCode("*:*:*").Code},
	}
	if roleMatchesProtectedAdminScope(otherScopeRole, protected) {
		t.Fatalf("expected admin role in another namespace not to match")
	}
}
