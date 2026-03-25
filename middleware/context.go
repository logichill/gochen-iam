package middleware

import (
	"gochen/httpx"
	"gochen/identity"
	"gochen/metadata"
)

// GetUserID 返回请求上下文中的用户 ID。
func GetUserID(ctx httpx.IRequestContext) int64 { return identity.GetUserID(ctx) }

// GetTenantID 返回请求上下文中的 tenant_id。
func GetTenantID(ctx httpx.IRequestContext) string { return metadata.GetTenantID(ctx) }
