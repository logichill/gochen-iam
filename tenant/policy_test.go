package tenant

import (
	"context"
	"testing"

	"gochen/contextx"
	"gochen/errors"
)

func TestCurrent_DefaultIsSingleMode(t *testing.T) {
	// 不设置任何环境变量，验证默认为 single 模式
	policy := Current()
	if policy.Mode != ModeSingle {
		t.Fatalf("expected single mode as default, got %s", policy.Mode)
	}
	if policy.SingleTenantID != DefaultSingleTenantID {
		t.Fatalf("expected default tenant id %s, got %s", DefaultSingleTenantID, policy.SingleTenantID)
	}
}

func TestCurrent_TenantModeWhenExplicitlySet(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeTenant))

	policy := Current()
	if policy.Mode != ModeTenant {
		t.Fatalf("expected tenant mode, got %s", policy.Mode)
	}
}

func TestCurrent_SingleModeFallsBackToDefaultTenantID(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeSingle))
	t.Setenv(EnvSingleTenantID, "")

	policy := Current()
	if policy.Mode != ModeSingle {
		t.Fatalf("expected single mode, got %s", policy.Mode)
	}
	if policy.SingleTenantID != DefaultSingleTenantID {
		t.Fatalf("expected default single tenant id %s, got %s", DefaultSingleTenantID, policy.SingleTenantID)
	}
}

func TestCurrent_InvalidModeFallsBackToDefaultSinglePolicy(t *testing.T) {
	t.Setenv(EnvTenantMode, "unexpected")
	t.Setenv(EnvSingleTenantID, "")

	policy := Current()
	if policy.Mode != ModeSingle {
		t.Fatalf("expected single mode fallback, got %s", policy.Mode)
	}
	if policy.SingleTenantID != DefaultSingleTenantID {
		t.Fatalf("expected default single tenant id %s, got %s", DefaultSingleTenantID, policy.SingleTenantID)
	}
}

func TestResolveTenantID_SingleModeIgnoresContextTenant(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeSingle))
	t.Setenv(EnvSingleTenantID, "single-tenant")

	tenantID, err := ResolveTenantID(context.Background())
	if err != nil {
		t.Fatalf("ResolveTenantID: %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestNormalizeTenantID_SingleModeRejectsMismatch(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeSingle))
	t.Setenv(EnvSingleTenantID, "single-tenant")

	_, err := NormalizeTenantID(context.Background(), "other-tenant")
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
}

func TestResolveRequestTenantID_SingleModeIgnoresCurrentTenantMismatch(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeSingle))
	t.Setenv(EnvSingleTenantID, "single-tenant")

	tenantID, err := ResolveRequestTenantID("", "other-tenant", true)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestResolveRequestTenantID_RequestHeaderWins(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeTenant))

	tenantID, err := ResolveRequestTenantID("tenant-b", "tenant-a", true)
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
