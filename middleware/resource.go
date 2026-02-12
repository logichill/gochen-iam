package middleware

import (
	"gochen/errorx"
	"gochen/httpx"
)

// IsAdmin 判断是否为系统管理员（system_admin）。
func IsAdmin(ctx httpx.IRequestContext) bool {
	return HasAnyRole(ctx, "system_admin")
}

// RequireSelfOrAdmin 要求“本人”或“管理员”。
func RequireSelfOrAdmin(ctx httpx.IRequestContext, targetUserID int64) error {
	if ctx == nil || ctx.GetUserID() == 0 {
		return errorx.New(errorx.Unauthorized, "用户未认证")
	}
	if IsAdmin(ctx) {
		return nil
	}
	if targetUserID <= 0 {
		return errorx.New(errorx.Validation, "target user_id is required")
	}
	if ctx.GetUserID() != targetUserID {
		return errorx.New(errorx.Forbidden, "无访问权限")
	}
	return nil
}

// RequireSameTenantOrAdmin 要求同租户或管理员（用于少量允许管理员跨租户的运维能力）。
func RequireSameTenantOrAdmin(ctx httpx.IRequestContext, targetTenantID string) error {
	if ctx == nil || ctx.GetUserID() == 0 {
		return errorx.New(errorx.Unauthorized, "用户未认证")
	}
	if IsAdmin(ctx) {
		return nil
	}
	return RequireSameTenant(ctx, targetTenantID)
}
