package middleware

import (
	"gochen/errorx"
	"gochen/httpx"
)

// RequireTenant 处理要求租户。
func RequireTenant(ctx httpx.IRequestContext) (string, error) {
	if ctx == nil {
		return "", errorx.New(errorx.Unauthorized, "用户未认证")
	}
	tenantID := GetTenantID(ctx)
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
	if GetTenantID(ctx) != targetTenantID {
		return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}
	return nil
}
