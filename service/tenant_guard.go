package service

import (
	"context"
	"strings"

	"gochen-iam/tenant"
	"gochen/errorx"
)

func TenantIDFromContext(ctx context.Context) (string, error) {
	return tenant.ResolveTenantID(ctx)
}

func NormalizeTenantID(ctx context.Context, targetTenantID string) (string, error) {
	return tenant.NormalizeTenantID(ctx, targetTenantID)
}

func RequireTenantMatch(ctx context.Context, targetTenantID string) (string, error) {
	resolution, err := resolveTenantAccess(ctx, targetTenantID)
	if err != nil {
		return "", err
	}
	return resolution.TenantID, nil
}

func RequireSameTenant(ctx context.Context, tenantIDs ...string) (string, error) {
	var tenantID string
	for _, current := range tenantIDs {
		current = strings.TrimSpace(current)
		if current == "" {
			return "", errorx.New(errorx.Validation, "target tenant_id is required")
		}
		if tenantID == "" {
			tenantID = current
			continue
		}
		if current != tenantID {
			return "", errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
		}
	}
	return RequireTenantMatch(ctx, tenantID)
}

func RequirePermissionInTenant(ctx context.Context, scopeAuthorizer *ScopeAuthorizer, permission, tenantID string) error {
	if scopeAuthorizer == nil {
		return nil
	}
	return scopeAuthorizer.RequirePermissionInTenant(ctx, permission, tenantID)
}

func PreflightTenant(ctx context.Context, scopeAuthorizer *ScopeAuthorizer, targetTenantID, permission string) (string, error) {
	tenantID, err := RequireTenantMatch(ctx, targetTenantID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(permission) != "" {
		if err := RequirePermissionInTenant(ctx, scopeAuthorizer, permission, tenantID); err != nil {
			return "", err
		}
	}
	return tenantID, nil
}

func PreflightSameTenant(ctx context.Context, scopeAuthorizer *ScopeAuthorizer, permission string, tenantIDs ...string) (string, error) {
	tenantID, err := RequireSameTenant(ctx, tenantIDs...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(permission) != "" {
		if err := RequirePermissionInTenant(ctx, scopeAuthorizer, permission, tenantID); err != nil {
			return "", err
		}
	}
	return tenantID, nil
}

func RequireTenantPermission(ctx context.Context, scopeAuthorizer *ScopeAuthorizer, permission, targetTenantID string) (string, error) {
	return PreflightTenant(ctx, scopeAuthorizer, targetTenantID, permission)
}

func RequireSameTenantPermission(ctx context.Context, scopeAuthorizer *ScopeAuthorizer, permission string, tenantIDs ...string) (string, error) {
	return PreflightSameTenant(ctx, scopeAuthorizer, permission, tenantIDs...)
}
