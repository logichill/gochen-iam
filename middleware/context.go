package middleware

import (
	ctxx "gochen/contextx"
	"gochen/httpx"
)

// GetUserID 返回请求上下文中的用户 ID。
func GetUserID(ctx httpx.IRequestContext) int64 { return ctxx.UserID(ctx) }

// GetTenantID 返回请求上下文中的 tenant_id。
func GetTenantID(ctx httpx.IRequestContext) string { return ctxx.TenantID(ctx) }
