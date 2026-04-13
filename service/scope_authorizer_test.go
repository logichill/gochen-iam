package service

import (
	"context"
	"testing"

	"gochen-iam/tenant"
	"gochen/authz"
)

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeShortCircuitsScopeLookup(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:read")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", ""); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeRejectsMismatchedTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:read")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", "tenant-b"); err == nil {
		t.Fatalf("expected mismatched tenant to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeStillRequiresPermission(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:list")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", ""); err == nil {
		t.Fatalf("expected missing permission to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_UsesPrincipalOutsideHTTP(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		TenantID:    "ignored",
		Permissions: []string{"api:role:read"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	authorizer := NewScopeAuthorizer(nil, nil)
	if err := authorizer.RequirePermissionInTenant(ctx, "api:role:read", ""); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}
