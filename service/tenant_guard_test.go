package service

import (
	"context"
	"net/http/httptest"
	"testing"

	iamauth "gochen-iam/auth"
	"gochen-iam/tenant"
	ctxx "gochen/contextx"
	httpx "gochen/httpx"
	nethttp "gochen/httpx/nethttp"
)

func newTenantGuardRequestContext(t *testing.T, tenantID string) httpx.IRequestContext {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/tenant-guard", nil)
	ctx, err := nethttp.NewBaseContext(rec, req)
	if err != nil {
		t.Fatalf("NewBaseContext: %v", err)
	}
	baseCtx, err := ctxx.WithTenantID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	return ctx.GetContext().WithContext(baseCtx)
}

func TestRequireTenantMatch_AllowsPlatformScopeCrossTenant(t *testing.T) {
	reqCtx := newTenantGuardRequestContext(t, "tenant-b")
	reqCtx = iamauth.WithActiveScope(reqCtx, 101, "/platform/", "platform")

	tenantID, err := RequireTenantMatch(reqCtx, "platform-tenant")
	if err != nil {
		t.Fatalf("RequireTenantMatch: %v", err)
	}
	if tenantID != "platform-tenant" {
		t.Fatalf("expected platform-tenant, got %s", tenantID)
	}
}

func TestRequireTenantMatch_RejectsCrossTenantWithoutPlatformScope(t *testing.T) {
	reqCtx := newTenantGuardRequestContext(t, "tenant-b")

	_, err := RequireTenantMatch(reqCtx, "platform-tenant")
	if err == nil {
		t.Fatalf("expected cross-tenant access to be rejected")
	}
}

func TestRequireTenantPermission_ReusesTenantGuardWhenAuthorizerUnavailable(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeRequired))
	reqCtx := newTenantGuardRequestContext(t, "tenant-a")

	tenantID, err := RequireTenantPermission(reqCtx, nil, "api:user:read", "tenant-a")
	if err != nil {
		t.Fatalf("RequireTenantPermission: %v", err)
	}
	if tenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", tenantID)
	}
}

func TestRequireSameTenantPermission_RejectsCrossTenantBeforePermissionCheck(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeRequired))
	reqCtx := newTenantGuardRequestContext(t, "tenant-a")

	_, err := RequireSameTenantPermission(reqCtx, nil, "api:user:write", "tenant-a", "tenant-b")
	if err == nil {
		t.Fatalf("expected cross-tenant access to be rejected")
	}
}

func TestPreflightTenant_WithoutPermissionStillChecksTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeRequired))
	reqCtx := newTenantGuardRequestContext(t, "tenant-a")

	tenantID, err := PreflightTenant(reqCtx, nil, "tenant-a", "")
	if err != nil {
		t.Fatalf("PreflightTenant: %v", err)
	}
	if tenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", tenantID)
	}
}
