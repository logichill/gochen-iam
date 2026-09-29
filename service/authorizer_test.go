package service

import (
	"context"
	"fmt"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
)

func TestIAMAuthorizerCreateResourceUsesContextTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"user:api:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	decision, err := authorizer.Authorize(ctx, "user:api:write", &iamentity.User{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := func() error {
		if !decision.IsAllowed() {
			return fmt.Errorf("not allowed")
		}
		return nil
	}(); err != nil {
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
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"user:api:*"},
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

	decision, err := authorizer.Authorize(ctx, "user:api:write", user, group)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != scoped.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode == "" {
		t.Fatalf("expected non-empty deny reason")
	}
}

func TestIAMAuthorizerDeniesCreateResourceWithForeignTenantBoundary(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   1,
		Permissions: []string{"user:api:*"},
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
	decision, err := authorizer.Authorize(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != scoped.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode == "" {
		t.Fatalf("expected non-empty deny reason")
	}
}

func TestIAMAuthorizerAllowsPlatformScopeCrossTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"role:api:*"},
		ActiveScopeID: 101,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 101, "platform")

	role := &iamentity.Role{TenantID: "tenant-b"}
	role.SetID(7)

	decision, err := authorizer.Authorize(ctx, "role:api:write", role)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := func() error {
		if !decision.IsAllowed() {
			return fmt.Errorf("not allowed")
		}
		return nil
	}(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
}

func TestIAMAuthorizerDeniesPlatformResourceOutsidePlatformScope(t *testing.T) {
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"tenant:api:write"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 7, "tenant")

	decision, err := authorizer.Authorize(ctx, "tenant:api:write", &iamentity.Tenant{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != scoped.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode == "" {
		t.Fatalf("expected non-empty deny reason")
	}
}

func TestIAMAuthorizerDeniesPlatformOwnedUserOutsidePlatformScopeInSingleTenant(t *testing.T) {
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 7, "tenant")
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
	decision, err := authorizer.Authorize(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Effect != scoped.EffectDeny {
		t.Fatalf("expected deny, got %s", decision.Effect)
	}
	if decision.ReasonCode == "" {
		t.Fatalf("expected non-empty deny reason")
	}
}

func TestIAMAuthorizerAllowsPlatformOwnedUserInPlatformScope(t *testing.T) {
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 1, "platform")
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
	decision, err := authorizer.Authorize(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := func() error {
		if !decision.IsAllowed() {
			return fmt.Errorf("not allowed")
		}
		return nil
	}(); err != nil {
		t.Fatalf("RequireAllow: %v", err)
	}
}

func TestIAMAuthorizerAllowsPlatformScopedMenuWrite(t *testing.T) {
	registry, err := NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := NewIAMAuthorizer(nil, registry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"menu:api:write"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 1, "platform")

	decision, err := authorizer.Authorize(ctx, "menu:api:write", &iamentity.MenuItem{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if err := func() error {
		if !decision.IsAllowed() {
			return fmt.Errorf("not allowed")
		}
		return nil
	}(); err != nil {
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

	ctx, err = WithSystemPrincipal(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("WithSystemPrincipal: %v", err)
	}

	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || !principal.IsSystem {
		t.Fatalf("expected system principal")
	}
	if got := contextx.TenantID(ctx); got != "tenant-b" {
		t.Fatalf("expected tenant-b, got %q", got)
	}
}
