package middleware

import (
	"gochen-iam/tenant"
	"gochen/errors"
	"gochen/httpx"
)

// RequireTenant 处理要求租户。
func RequireTenant(ctx httpx.IRequestContext) (string, error) {
	if ctx == nil {
		return "", errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	return tenant.ResolveTenantID(ctx)
}

// RequireSameTenant 要求当前请求 tenant 与目标 tenant 一致。
func RequireSameTenant(ctx httpx.IRequestContext, targetTenantID string) error {
	if ctx == nil {
		return errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	_, err := tenant.NormalizeTenantID(ctx, targetTenantID)
	return err
}
