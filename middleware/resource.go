package middleware

import (
	"gochen/errorx"
	"gochen/httpx"
)

// IsAdmin 判断当前 active scope 是否具备管理员级全量权限。
func IsAdmin(ctx httpx.IRequestContext) bool {
	return HasPermission(ctx, PermissionCode("*:*:*").Code)
}

// RequireSelfOrAdmin 要求“本人”或“管理员”。
func RequireSelfOrAdmin(ctx httpx.IRequestContext, targetUserID int64) error {
	if ctx == nil || GetUserID(ctx) == 0 {
		return errorx.New(errorx.Unauthorized, "用户未认证")
	}
	if IsAdmin(ctx) {
		return nil
	}
	if targetUserID <= 0 {
		return errorx.New(errorx.Validation, "target user_id is required")
	}
	if GetUserID(ctx) != targetUserID {
		return errorx.New(errorx.Forbidden, "无访问权限")
	}
	return nil
}

// RequireSameTenantOrAdmin 要求同租户或管理员（用于少量允许管理员跨租户的运维能力）。
func RequireSameTenantOrAdmin(ctx httpx.IRequestContext, targetTenantID string) error {
	if ctx == nil || GetUserID(ctx) == 0 {
		return errorx.New(errorx.Unauthorized, "用户未认证")
	}
	if IsAdmin(ctx) {
		return nil
	}
	return RequireSameTenant(ctx, targetTenantID)
}
