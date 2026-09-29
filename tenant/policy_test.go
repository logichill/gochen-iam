package tenant

import (
	"context"
	"testing"

	"gochen/contextx"
	"gochen/errors"
)

func TestNormalizePolicyDefaults(t *testing.T) {
	for _, input := range []Policy{{}, {Mode: ModeSingle}, {Mode: "unexpected"}} {
		policy := NormalizePolicy(input)
		if policy.Mode != ModeSingle || policy.SingleTenantID != DefaultSingleTenantID {
			t.Fatalf("NormalizePolicy(%+v) = %+v", input, policy)
		}
	}
	if policy := NormalizePolicy(Policy{Mode: ModeTenant}); policy.Mode != ModeTenant {
		t.Fatalf("expected tenant mode, got %+v", policy)
	}
}

func TestCurrentContextRequiresExplicitSinglePolicy(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeSingle))
	t.Setenv(EnvSingleTenantID, "environment-tenant")
	for _, ctx := range []context.Context{nil, context.Background()} {
		if policy := CurrentContext(ctx); policy.Mode != ModeTenant {
			t.Fatalf("missing policy must preserve tenant isolation, got %+v", policy)
		}
		if _, ok := PolicyFromContext(ctx); ok {
			t.Fatal("unexpected explicit policy")
		}
	}
	if _, err := ResolveTenantID(context.Background()); !errors.Is(err, errors.Validation) {
		t.Fatalf("missing tenant must fail, got %v", err)
	}
	ctx := WithPolicy(context.Background(), Policy{Mode: ModeSingle, SingleTenantID: "configured-tenant"})
	if policy := CurrentContext(ctx); policy.SingleTenantID != "configured-tenant" {
		t.Fatalf("explicit policy = %+v", policy)
	}
}

func TestResolveTenantID_SingleModeIgnoresContextTenant(t *testing.T) {
	policy := Policy{Mode: ModeSingle, SingleTenantID: "single-tenant"}

	tenantID, err := ResolveTenantID(WithPolicy(context.Background(), policy))
	if err != nil {
		t.Fatalf("ResolveTenantID: %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestNormalizeTenantID_SingleModeRejectsMismatch(t *testing.T) {
	policy := Policy{Mode: ModeSingle, SingleTenantID: "single-tenant"}

	_, err := NormalizeTenantID(WithPolicy(context.Background(), policy), "other-tenant")
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
}

func TestResolveRequestTenantID_SingleModeIgnoresCurrentTenantMismatch(t *testing.T) {
	policy := Policy{Mode: ModeSingle, SingleTenantID: "single-tenant"}

	tenantID, err := ResolveRequestTenantIDWithPolicy(policy, "", "other-tenant", true)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestResolveRequestTenantID_RequestHeaderWins(t *testing.T) {
	policy := Policy{Mode: ModeTenant}

	tenantID, err := ResolveRequestTenantIDWithPolicy(policy, "tenant-b", "tenant-a", true)
	if err != nil {
		t.Fatalf("ResolveRequestTenantID: %v", err)
	}
	if tenantID != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", tenantID)
	}
}

func TestResolverUsesContextTenant(t *testing.T) {
	ctx, err := contextx.WithTenantID(context.Background(), "context-tenant")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	tenantID, err := (Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		t.Fatalf("Resolver.ResolveTenantID: %v", err)
	}
	if tenantID != "context-tenant" {
		t.Fatalf("expected context-tenant, got %s", tenantID)
	}
}
