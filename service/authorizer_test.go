package service

import (
	"context"
	"gochen/ident"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	auth "gochen/auth"
	"gochen/contextx"
)

func TestIAMAuthorizerCreateResourceUsesContextTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"api:user:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
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
	if got := decision.AuthorizedResources[0].OwnerID; got != tenantOwnerID("tenant-a") {
		t.Fatalf("expected tenant-a, got %q", got)
	}
}

func TestIAMAuthorizerDeniesMixedTenantResources(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"api:user:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	user := &iamentity.User{TenantID: "tenant-a"}
	user.SetID(1)
	group := &iamentity.Group{TenantID: "tenant-b"}
	group.SetID(2)

	decision, err := authorizer.Authorize(ctx, "api:user:write", user, group)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != auth.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "cross_tenant_resource_set" {
		t.Fatalf("expected cross_tenant_resource_set, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerDeniesCreateResourceWithForeignTenantBoundary(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"api:user:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "tenant-b",
		HomeTenantID:   "tenant-b",
		HomeScopeID:    11,
		ManagedScopeID: 11,
		OwnerID:        TenantOwnerID("tenant-b"),
	}
	decision, err := authorizer.Authorize(ctx, "api:user:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != auth.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "tenant_scope_denied" {
		t.Fatalf("expected tenant_scope_denied, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerAllowsPlatformScopeCrossTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:role:*"},
		ActiveScopeID: 101,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 101, "platform")

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
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:tenant:write"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 7, "tenant")

	decision, err := authorizer.Authorize(ctx, "api:tenant:write", &iamentity.Tenant{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != auth.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "platform_scope_denied" {
		t.Fatalf("expected platform_scope_denied, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerDeniesPlatformOwnedUserOutsidePlatformScopeInSingleTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "erp-demo")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:user:*"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 7, "tenant")
	ctx, err = contextx.WithTenantID(ctx, "erp-demo")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "erp-demo",
		OwnerID:        "platform",
		ManagedScopeID: 1,
	}
	user.SetID(9)
	decision, err := authorizer.Authorize(ctx, "api:user:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != auth.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode != "platform_scope_denied" {
		t.Fatalf("expected platform_scope_denied, got %q", decision.ReasonCode)
	}
}

func TestIAMAuthorizerAllowsPlatformOwnedUserInPlatformScope(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "erp-demo")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:user:*"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = contextx.WithTenantID(ctx, "erp-demo")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "erp-demo",
		OwnerID:        "platform",
		ManagedScopeID: 1,
	}
	user.SetID(9)
	decision, err := authorizer.Authorize(ctx, "api:user:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := decision.RequireAllow(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
}

func TestIAMAuthorizerAllowsPlatformScopedMenuWrite(t *testing.T) {
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:menu:write"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")

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
	if got := decision.AuthorizedResources[0].Kind; got != MenuResourceKind {
		t.Fatalf("expected %q resource kind, got %q", MenuResourceKind, got)
	}
}

func TestWithSystemPrincipal_ReplaysAuthorizationRuntime(t *testing.T) {
	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID: 3,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithExecutionMetadata(ctx, auth.ExecutionMetadata{
		RequestID:  "req-iam",
		DecisionID: "dec-iam",
	})
	if err != nil {
		t.Fatalf("WithExecutionMetadata: %v", err)
	}
	ctx, err = auth.WithSnapshotVersion(ctx, "snap-old")
	if err != nil {
		t.Fatalf("WithSnapshotVersion: %v", err)
	}

	ctx, err = WithSystemPrincipal(ctx, "tenant-b", auth.ExecutionMetadata{JobID: "job-iam"})
	if err != nil {
		t.Fatalf("WithSystemPrincipal: %v", err)
	}

	eval, err := auth.EvalContextFromContext(ctx)
	if err != nil {
		t.Fatalf("EvalContextFromContext: %v", err)
	}
	if !eval.Principal.IsSystem {
		t.Fatalf("expected system principal")
	}
	if got := contextx.TenantID(ctx); got != "tenant-b" {
		t.Fatalf("expected tenant-b, got %q", got)
	}
	if eval.Consistency != auth.ConsistencyModeStrong {
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
