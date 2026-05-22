package guard

import (
	"testing"

	iamaccess "gochen-iam/access"
	"gochen/errors"
)

func TestRequireSameTenantAllowsDifferentManagedScopesWhenTenantMatches(t *testing.T) {
	err := RequireSameTenant(
		iamaccess.ResourceConstraint{Kind: "iam.user", ResourceID: "1", TenantID: "tenant-a", ManagedScopeID: 10},
		iamaccess.ResourceConstraint{Kind: "iam.role", ResourceID: "2", TenantID: "tenant-a", ManagedScopeID: 20},
	)
	if err != nil {
		t.Fatalf("expected same tenant resources to pass: %v", err)
	}
}

func TestRequireSameTenantRejectsMixedTenantBoundaries(t *testing.T) {
	err := RequireSameTenant(
		iamaccess.ResourceConstraint{Kind: "iam.user", ResourceID: "1", TenantID: "tenant-a", ManagedScopeID: 10},
		iamaccess.ResourceConstraint{Kind: "iam.role", ResourceID: "2", ManagedScopeID: 20},
	)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected missing tenant boundary to be forbidden, got %v", err)
	}

	err = RequireSameTenant(
		iamaccess.ResourceConstraint{Kind: "iam.user", ResourceID: "1", TenantID: "tenant-a", ManagedScopeID: 10},
		iamaccess.ResourceConstraint{Kind: "iam.role", ResourceID: "2", TenantID: "tenant-b", ManagedScopeID: 20},
	)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected cross-tenant resources to be forbidden, got %v", err)
	}
}
