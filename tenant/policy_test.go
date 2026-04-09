package tenant

import (
	"context"
	"testing"

	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

func TestCurrent_DefaultIsFixedMode(t *testing.T) {
	// 不设置任何环境变量，验证默认为 fixed 模式
	policy := Current()
	if policy.Mode != ModeFixed {
		t.Fatalf("expected fixed mode as default, got %s", policy.Mode)
	}
	if policy.FixedTenantID != DefaultFixedTenantID {
		t.Fatalf("expected default tenant id %s, got %s", DefaultFixedTenantID, policy.FixedTenantID)
	}
}

func TestCurrent_RequiredModeWhenExplicitlySet(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeRequired))

	policy := Current()
	if policy.Mode != ModeRequired {
		t.Fatalf("expected required mode, got %s", policy.Mode)
	}
}

func TestCurrent_FixedModeFallsBackToDefaultTenantID(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeFixed))
	t.Setenv(EnvFixedTenantID, "")

	policy := Current()
	if policy.Mode != ModeFixed {
		t.Fatalf("expected fixed mode, got %s", policy.Mode)
	}
	if policy.FixedTenantID != DefaultFixedTenantID {
		t.Fatalf("expected default fixed tenant id %s, got %s", DefaultFixedTenantID, policy.FixedTenantID)
	}
}

func TestCurrent_InvalidModeFallsBackToDefaultFixedPolicy(t *testing.T) {
	t.Setenv(EnvTenantMode, "unexpected")
	t.Setenv(EnvFixedTenantID, "")

	policy := Current()
	if policy.Mode != ModeFixed {
		t.Fatalf("expected fixed mode fallback, got %s", policy.Mode)
	}
	if policy.FixedTenantID != DefaultFixedTenantID {
		t.Fatalf("expected default fixed tenant id %s, got %s", DefaultFixedTenantID, policy.FixedTenantID)
	}
}

func TestResolveTenantID_FixedModeIgnoresContextTenant(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeFixed))
	t.Setenv(EnvFixedTenantID, "fixed-tenant")

	tenantID, err := ResolveTenantID(context.Background())
	if err != nil {
		t.Fatalf("ResolveTenantID: %v", err)
	}
	if tenantID != "fixed-tenant" {
		t.Fatalf("expected fixed-tenant, got %s", tenantID)
	}
}

func TestNormalizeTenantID_FixedModeRejectsMismatch(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeFixed))
	t.Setenv(EnvFixedTenantID, "fixed-tenant")

	_, err := NormalizeTenantID(context.Background(), "other-tenant")
	if !errorx.Is(err, errorx.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
}

func TestResolveRequestTenantID_FixedModeRejectsTokenMismatch(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeFixed))
	t.Setenv(EnvFixedTenantID, "fixed-tenant")

	_, err := ResolveRequestTenantID("", "other-tenant", true)
	if !errorx.Is(err, errorx.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
}

func TestResolveRequestTenantIDWithScope_PlatformScopeAllowsCrossTenantHeader(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeRequired))

	tenantID, err := ResolveRequestTenantIDWithScope("tenant-b", "platform-tenant", "platform", true)
	if err != nil {
		t.Fatalf("ResolveRequestTenantIDWithScope: %v", err)
	}
	if tenantID != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", tenantID)
	}
}

func TestInstallTenantResolverRequiresExplicitOptIn(t *testing.T) {
	t.Setenv(EnvTenantMode, string(ModeFixed))
	t.Setenv(EnvFixedTenantID, "fixed-tenant")

	domaincrud.SetTenantResolver(nil)
	defer domaincrud.SetTenantResolver(nil)

	_, err := domaincrud.ResolveTenantID(context.Background())
	if !errorx.Is(err, errorx.InvalidInput) {
		t.Fatalf("expected default resolver InvalidInput before install, got %v", err)
	}

	InstallTenantResolver()

	tenantID, err := domaincrud.ResolveTenantID(context.Background())
	if err != nil {
		t.Fatalf("ResolveTenantID after install: %v", err)
	}
	if tenantID != "fixed-tenant" {
		t.Fatalf("expected fixed-tenant, got %s", tenantID)
	}
}
