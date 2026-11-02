package service

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	coreauth "gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
)

func TestIAMAuthorizerAuthorizeUsesContextTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 101,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 101, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(101))
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	decision, err := authorizer.Authorize(ctx, coreauth.Request{
		Resource:   "user",
		Action:     "write",
		Permission: "user:api:write",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed, got deny: %s", decision.Reason)
	}
	if got, want := decision.Spec.Canonical(), DataScopeSpec(ctx).Canonical(); got != want {
		t.Fatalf("expected data scope spec %q, got %q", want, got)
	}
}

func TestIAMAuthorizerDeniesMixedTenantResources(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:   "1",
		Permissions: []string{"user:api:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	user := &iamentity.User{TenantID: "tenant-a"}
	user.SetID(1)
	group := &iamentity.Group{TenantID: "tenant-b"}
	group.SetID(2)

	decision, err := authorizer.AuthorizeTargets(ctx, "user:api:write", user, group)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected mixed tenant targets to be denied")
	}
	if decision.Reason != ReasonCrossTenantDenied {
		t.Fatalf("expected %q, got %q", ReasonCrossTenantDenied, decision.Reason)
	}
}

func TestIAMAuthorizerDeniesCreateResourceWithForeignTenantBoundary(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:   "1",
		Permissions: []string{"user:api:*"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "tenant-b",
		HomeTenantID:   "tenant-b",
		HomeScopeID:    11,
		ManagedScopeID: 11,
		OwnerID:        TenantOwnerID("tenant-b"),
	}
	decision, err := authorizer.AuthorizeTargets(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected foreign tenant target to be denied")
	}
	if decision.Reason != ReasonTenantScopeDenied {
		t.Fatalf("expected %q, got %q", ReasonTenantScopeDenied, decision.Reason)
	}
}

func TestIAMAuthorizerAllowsPlatformScopeCrossTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"role:api:*"},
		ActiveScopeID: 101,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 101, "platform")

	role := &iamentity.Role{TenantID: "tenant-b"}
	role.SetID(7)

	decision, err := authorizer.AuthorizeTargets(ctx, "role:api:write", role)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected platform scope to cross tenant, got deny: %s", decision.Reason)
	}
}

func TestIAMAuthorizerDeniesPlatformResourceOutsidePlatformScope(t *testing.T) {
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"tenant:api:write"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 7, "tenant")

	decision, err := authorizer.Authorize(ctx, coreauth.Request{
		Resource:   "tenant",
		Action:     "write",
		Permission: "tenant:api:write",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected platform resource to be denied outside platform scope")
	}
	if decision.Reason != ReasonPlatformScopeDenied {
		t.Fatalf("expected %q, got %q", ReasonPlatformScopeDenied, decision.Reason)
	}
}

func TestIAMAuthorizerManagedTargetUsesDataScopeSpec(t *testing.T) {
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "erp-demo")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 7,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 7, "tenant")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(7))
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "erp-demo",
		OwnerID:        "platform",
		ManagedScopeID: 1,
	}
	user.SetID(9)
	decision, err := authorizer.AuthorizeTargets(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected tenant-scoped target to be allowed, got deny: %s", decision.Reason)
	}
	if got, want := decision.Spec.Canonical(), DataScopeSpec(ctx).Canonical(); got != want {
		t.Fatalf("expected data scope spec %q, got %q", want, got)
	}
}

func TestIAMAuthorizerAllowsPlatformOwnedUserInPlatformScope(t *testing.T) {
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "erp-demo")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 1, "platform")

	user := &iamentity.User{
		TenantID:       "erp-demo",
		OwnerID:        "platform",
		ManagedScopeID: 1,
	}
	user.SetID(9)
	decision, err := authorizer.AuthorizeTargets(ctx, "user:api:write", user)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected platform scope to allow the target, got deny: %s", decision.Reason)
	}
}

func TestIAMAuthorizerAllowsPlatformScopedMenuWrite(t *testing.T) {
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"menu:api:write"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "erp-demo"}), 1, "platform")

	decision, err := authorizer.Authorize(ctx, coreauth.Request{
		Resource:   "menu",
		Action:     "write",
		Permission: "menu:api:write",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected platform scoped menu write to be allowed, got deny: %s", decision.Reason)
	}
	if !decision.Spec.IsAll() {
		t.Fatalf("expected platform resource to use the all spec, got %q", decision.Spec.Canonical())
	}
}

func TestWithSystemPrincipal_ReplaysAuthorizationRuntime(t *testing.T) {
	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID: "3",
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
	identity, ok := coreauth.PrincipalFromContext(ctx)
	if !ok || !identity.System || identity.TenantID != "tenant-b" {
		t.Fatalf("expected root system identity in tenant-b, got %+v", identity)
	}
}

func TestAuthorizer_MultiTenantFailsClosedWithoutActiveScopeID(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(&ScopeAuthorizer{})

	// Principal 没有 ActiveScopeID (ActiveScopeID <= 0)
	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 0,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	targetUser := &iamentity.User{TenantID: "tenant-a"}
	decision, err := authorizer.AuthorizeTargets(ctx, "user:api:read", targetUser)
	if err != nil {
		t.Fatalf("AuthorizeTargets: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected fail-closed when ActiveScopeID <= 0 in multi-tenant mode, got allowed")
	}
}

func TestIAMAuthorizerRejectsNilScopeAuthorizerInMultiTenant(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	authorizer := NewIAMAuthorizer(nil)

	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: 10,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	targetUser := &iamentity.User{TenantID: "tenant-a"}
	targetUser.SetID(1)
	_, err = authorizer.AuthorizeTargets(ctx, "user:api:read", targetUser)
	if err == nil {
		t.Fatal("expected error when scopeAuthorizer is nil in multi-tenant mode, got nil (fail-open)")
	}
}
