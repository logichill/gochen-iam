package service

import (
	"context"
	"net/http/httptest"
	"testing"

	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	"gochen/auth"
	"gochen/contextx"
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
	baseCtx, err := contextx.WithTenantID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	baseCtx, err = auth.WithPrincipal(context.Background(), auth.Principal{SubjectID: 1})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	baseCtx, err = contextx.WithTenantID(baseCtx, tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	return ctx.RequestContext().WithContext(baseCtx)
}

func withPermissions(t *testing.T, reqCtx httpx.IRequestContext, permissions ...string) httpx.IRequestContext {
	t.Helper()
	derived := iamauth.WithPermissions(reqCtx, permissions)
	principal, _ := auth.PrincipalFromContext(derived)
	principal.Permissions = permissions
	updated, err := auth.WithPrincipal(derived, principal)
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	if tenantID := contextx.TenantID(derived); tenantID != "" {
		updated, err = contextx.WithTenantID(updated, tenantID)
		if err != nil {
			t.Fatalf("WithTenantID: %v", err)
		}
	}
	return derived.WithContext(updated)
}

func withActiveScope(t *testing.T, reqCtx httpx.IRequestContext, scopeID int64, scopeCode, scopeType string) httpx.IRequestContext {
	t.Helper()
	derived := iamauth.WithActiveScope(reqCtx, scopeID, scopeType)
	principal, _ := auth.PrincipalFromContext(derived)
	principal.ActiveScopeID = scopeID
	updated, err := auth.WithPrincipal(iamauth.BindActiveScopeContext(derived, scopeID, scopeType), principal)
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	if tenantID := contextx.TenantID(derived); tenantID != "" {
		updated, err = contextx.WithTenantID(updated, tenantID)
		if err != nil {
			t.Fatalf("WithTenantID: %v", err)
		}
	}
	return derived.WithContext(updated)
}

func TestRequireTenantMatch_AllowsPlatformScopeCrossTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	reqCtx := withActiveScope(t, newTenantGuardRequestContext(t, "tenant-b"), 101, "/platform/", "platform")

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
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))
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
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))
	reqCtx := newTenantGuardRequestContext(t, "tenant-a")

	_, err := RequireSameTenantPermission(reqCtx, nil, "api:user:write", "tenant-a", "tenant-b")
	if err == nil {
		t.Fatalf("expected cross-tenant access to be rejected")
	}
}

func TestPreflightTenant_WithoutPermissionStillChecksTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))
	reqCtx := newTenantGuardRequestContext(t, "tenant-a")

	tenantID, err := PreflightTenant(reqCtx, nil, "tenant-a", "")
	if err != nil {
		t.Fatalf("PreflightTenant: %v", err)
	}
	if tenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", tenantID)
	}
}

func TestRequireTenantMatch_FixedModeUsesConfiguredTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := newTenantGuardRequestContext(t, "ignored")

	tenantID, err := RequireTenantMatch(reqCtx, "")
	if err != nil {
		t.Fatalf("RequireTenantMatch: %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestRequireTenantMatch_SingleModeRejectsMismatchedTarget(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := newTenantGuardRequestContext(t, "ignored")

	if _, err := RequireTenantMatch(reqCtx, "tenant-b"); err == nil {
		t.Fatalf("expected fixed tenant mismatch to be rejected")
	}
}

func TestRequireTenantPermission_SingleModeStillChecksPermission(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:user:read")

	tenantID, err := RequireTenantPermission(reqCtx, NewScopeAuthorizer(nil, nil), "api:user:read", "")
	if err != nil {
		t.Fatalf("RequireTenantPermission: %v", err)
	}
	if tenantID != "single-tenant" {
		t.Fatalf("expected single-tenant, got %s", tenantID)
	}
}

func TestRequireTenantPermission_SingleModeRejectsMissingPermission(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:user:list")

	err := iammw.RequirePermission(reqCtx, "api:user:read")
	if err == nil {
		t.Fatalf("expected middleware permission helper to reject missing permission")
	}

	if _, err := RequireTenantPermission(reqCtx, NewScopeAuthorizer(nil, nil), "api:user:read", ""); err == nil {
		t.Fatalf("expected missing permission to be rejected even in single mode")
	}
}
