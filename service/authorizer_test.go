package service

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	"gochen/authz"
)

func TestIAMAuthorizerCreateResourceUsesContextTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:   1,
		TenantID:    "tenant-a",
		Permissions: []string{"*:*:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	decision, err := authorizer.Authorize(ctx, "api:user:write", &iamentity.User{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := decision.RequireAllow(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
	if len(decision.AuthorizedResources) != 1 {
		t.Fatalf("expected 1 authorized resource, got %d", len(decision.AuthorizedResources))
	}
	if got := decision.AuthorizedResources[0].TenantID; got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", got)
	}
}

func TestIAMAuthorizerDeniesMixedTenantResources(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:   1,
		TenantID:    "tenant-a",
		Permissions: []string{"*:*:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	user := &iamentity.User{TenantID: "tenant-a"}
	user.SetID(1)
	group := &iamentity.Group{TenantID: "tenant-b"}
	group.SetID(2)

	decision, err := authorizer.Authorize(ctx, "api:user:write", user, group)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != authz.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "cross_tenant_resource_set" {
		t.Fatalf("expected cross_tenant_resource_set, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerDeniesCreateResourceWithForeignTenantBoundary(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:   1,
		TenantID:    "tenant-a",
		Permissions: []string{"*:*:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	user := &iamentity.User{
		TenantID:  "tenant-b",
		ScopeType: string(iammw.ScopeTenant),
		ScopeCode: "tenant:tenant-b",
	}
	decision, err := authorizer.Authorize(ctx, "api:user:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != authz.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "tenant_scope_denied" {
		t.Fatalf("expected tenant_scope_denied, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerAllowsPlatformScopeCrossTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		Permissions:     []string{"*:*:*"},
		ActiveScopeType: string(iammw.ScopePlatform),
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	role := &iamentity.Role{TenantID: "tenant-b"}
	role.SetID(7)

	decision, err := authorizer.Authorize(ctx, "api:role:write", role)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := decision.RequireAllow(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
}

func TestIAMAuthorizerDeniesPlatformResourceOutsidePlatformScope(t *testing.T) {
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		Permissions:     []string{"api:tenant:write"},
		ActiveScopeType: string(iammw.ScopeTenant),
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	decision, err := authorizer.Authorize(ctx, "api:tenant:write", &iamentity.Tenant{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != authz.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "platform_scope_denied" {
		t.Fatalf("expected platform_scope_denied, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerAllowsPlatformScopedMenuWrite(t *testing.T) {
	authorizer, err := NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		Permissions:     []string{"api:menu:write"},
		ActiveScopeType: string(iammw.ScopePlatform),
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	decision, err := authorizer.Authorize(ctx, "api:menu:write", &iamentity.MenuItem{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := decision.RequireAllow(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
	if len(decision.AuthorizedResources) != 1 {
		t.Fatalf("expected 1 authorized resource, got %d", len(decision.AuthorizedResources))
	}
	if got := decision.AuthorizedResources[0].ScopeType; got != string(iammw.ScopePlatform) {
		t.Fatalf("expected platform scope type, got %q", got)
	}
}

func TestWithSystemPrincipal_ReplaysAuthorizationRuntime(t *testing.T) {
	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID: 3,
		TenantID:  "tenant-a",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithExecutionMetadata(ctx, authz.ExecutionMetadata{
		RequestID:  "req-iam",
		DecisionID: "dec-iam",
	})
	if err != nil {
		t.Fatalf("WithExecutionMetadata: %v", err)
	}
	ctx, err = authz.WithSnapshotVersion(ctx, "snap-old")
	if err != nil {
		t.Fatalf("WithSnapshotVersion: %v", err)
	}

	ctx, err = WithSystemPrincipal(ctx, "tenant-b", authz.ExecutionMetadata{JobID: "job-iam"})
	if err != nil {
		t.Fatalf("WithSystemPrincipal: %v", err)
	}

	eval, err := authz.EvalContextFromContext(ctx)
	if err != nil {
		t.Fatalf("EvalContextFromContext: %v", err)
	}
	if !eval.Principal.IsSystem {
		t.Fatalf("expected system principal")
	}
	if eval.Principal.TenantID != "tenant-b" {
		t.Fatalf("expected tenant-b, got %q", eval.Principal.TenantID)
	}
	if eval.Consistency != authz.ConsistencyModeStrong {
		t.Fatalf("expected strong consistency, got %q", eval.Consistency)
	}
	if eval.Execution.JobID != "job-iam" {
		t.Fatalf("expected job-iam, got %q", eval.Execution.JobID)
	}
	if eval.Execution.RequestID != "" {
		t.Fatalf("expected request id cleared, got %q", eval.Execution.RequestID)
	}
	if eval.Execution.DecisionID != "" {
		t.Fatalf("expected decision id cleared, got %q", eval.Execution.DecisionID)
	}
	if eval.SnapshotVersion != "job:job-iam" {
		t.Fatalf("expected replay snapshot job:job-iam, got %q", eval.SnapshotVersion)
	}
}
