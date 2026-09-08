package group

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen/auth/scoped"
	"gochen/errors"
	"gochen/testkit"
)

func TestDerivedHierarchyConstraintKeepsAuthorizedBoundary(t *testing.T) {
	r, err := NewGroupRepository(&fakeOrm{baseModel: &capturingModel{}}, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		tenant        string
		scope         int64
		explicitChild bool
		forbidden     bool
	}{
		{name: "same boundary", tenant: "tenant-a", scope: 10},
		{name: "different tenant", tenant: "tenant-b", scope: 10, forbidden: true},
		{name: "different scope", tenant: "tenant-a", scope: 20, forbidden: true},
		{name: "explicit stale child snapshot", tenant: "tenant-a", scope: 10, explicitChild: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := &iamentity.Group{TenantID: tc.tenant, ManagedScopeID: tc.scope}
			child.ID, child.Version = 2, 9
			parent := scoped.ResourceConstraint{Kind: groupResourceKind, ResourceID: "1", TenantID: "tenant-a", ManagedScopeID: 10, Revision: "4"}
			resources := []scoped.ResourceConstraint{parent}
			if tc.explicitChild {
				explicit := parent
				explicit.ResourceID, explicit.Revision = "2", "8"
				resources = append(resources, explicit)
			}
			ctx := scoped.WithConstraint(context.Background(), scoped.SingleEntityConstraint(groupResourceKind, scoped.WriteConstraint{Resources: resources}))
			derived, err := r.derivedGroupConstraintCtx(ctx, 1, child)
			if tc.forbidden {
				if !errors.Is(err, errors.Forbidden) {
					t.Fatalf("unauthorized boundary accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			guard, ok := scoped.ConstraintFrom(derived, groupResourceKind)
			if !ok {
				t.Fatal("missing child guard")
			}
			resource, err := guard.RequireResource(groupResourceKind, "2")
			wantRevision := "9"
			if tc.explicitChild {
				wantRevision = "8"
			}
			if err != nil || resource.Revision != wantRevision || resource.TenantID != "tenant-a" || resource.ManagedScopeID != 10 {
				t.Fatalf("child guard changed authorization snapshot: %+v %v", resource, err)
			}
		})
	}
}
