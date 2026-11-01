package middleware

import (
	"strconv"

	"gochen/contextx"
	"gochen/httpx"
)

// GetUserID 返回请求上下文中的用户 ID。
//
// IAM 的用户 ID 是数值主键；框架主体是规范十进制字符串，
// 无法解析时按未认证返回 0。
func GetUserID(ctx httpx.IRequestContext) int64 {
	userID, err := strconv.ParseInt(contextx.UserID(ctx), 10, 64)
	if err != nil {
		return 0
	}
	return userID
}

// GetTenantID 返回请求上下文中的 tenant_id。
func GetTenantID(ctx httpx.IRequestContext) string { return contextx.TenantID(ctx) }
