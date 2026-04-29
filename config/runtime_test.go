package config

import (
	"testing"
	"time"
)

func TestNormalizeRuntimeConfig(t *testing.T) {
	cfg := NormalizeRuntimeConfig(&RuntimeConfig{
		TenantMode:     " SINGLE ",
		SingleTenantID: "",
		TenantHeader:   "",
	})

	if cfg.TenantMode != "single" {
		t.Fatalf("TenantMode = %q, want single", cfg.TenantMode)
	}
	if cfg.SingleTenantID != "default" {
		t.Fatalf("SingleTenantID = %q, want default", cfg.SingleTenantID)
	}
	if cfg.AccessTokenTTL != 24*time.Hour {
		t.Fatalf("AccessTokenTTL = %s, want 24h", cfg.AccessTokenTTL)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")
	t.Setenv("IAM_SINGLE_TENANT_ID", "tenant-from-env")
	t.Setenv("AUTH_SECRET", "env-secret")
	t.Setenv("AUTH_ACCESS_TOKEN_TTL", "2h")
	t.Setenv("AUTH_REQUIRE_TENANT", "true")

	cfg := ApplyEnvOverrides(&RuntimeConfig{})
	if cfg.TenantMode != "tenant" {
		t.Fatalf("TenantMode = %q, want tenant", cfg.TenantMode)
	}
	if cfg.SingleTenantID != "tenant-from-env" {
		t.Fatalf("SingleTenantID = %q, want tenant-from-env", cfg.SingleTenantID)
	}
	if cfg.SecretKey != "env-secret" {
		t.Fatalf("SecretKey = %q, want env-secret", cfg.SecretKey)
	}
	if cfg.AccessTokenTTL != 2*time.Hour {
		t.Fatalf("AccessTokenTTL = %s, want 2h", cfg.AccessTokenTTL)
	}
	if !cfg.RequireTenant {
		t.Fatal("RequireTenant = false, want true")
	}
}

func TestValidateRuntimeConfig(t *testing.T) {
	if err := ValidateRuntimeConfig(&RuntimeConfig{
		TenantMode:     "single",
		SingleTenantID: "demo",
		SecretKey:      "secret",
	}, "production", true); err != nil {
		t.Fatalf("ValidateRuntimeConfig() error = %v", err)
	}

	if err := ValidateRuntimeConfig(&RuntimeConfig{
		TenantMode: "invalid",
	}, "development", false); err == nil {
		t.Fatal("expected invalid tenant_mode error")
	}

	if err := ValidateRuntimeConfig(&RuntimeConfig{
		TenantMode:      "single",
		SingleTenantID:  "demo",
		AllowQueryToken: true,
		SecretKey:       "secret",
	}, "production", true); err == nil {
		t.Fatal("expected production query token error")
	}
}
