package middleware

import (
	"gochen/errorx"
	"gochen/httpx"
)

// RequireTenant 要求请求上下文中已注入 tenant_id（通常来自 Header: X-Tenant-ID）。
func RequireTenant(ctx httpx.IRequestContext) (string, error) {
	if ctx == nil {
		return "", errorx.New(errorx.Unauthorized, "用户未认证")
	}
	tenantID := ctx.GetTenantID()
	if tenantID == "" {
		return "", errorx.New(errorx.Validation, "tenant_id is required")
	}
	return tenantID, nil
}

// RequireSameTenant 要求当前请求 tenant 与目标 tenant 一致。
func RequireSameTenant(ctx httpx.IRequestContext, targetTenantID string) error {
	if ctx == nil {
		return errorx.New(errorx.Unauthorized, "用户未认证")
	}
	if targetTenantID == "" {
		return errorx.New(errorx.Validation, "target tenant_id is required")
	}
	if ctx.GetTenantID() != targetTenantID {
		return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}
	return nil
}
