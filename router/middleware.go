package router

import (
	"gochen-iam/auth"
	iammw "gochen-iam/middleware"
	httpx "gochen/httpx"
)

// WithRoles 将角色列表写入请求上下文。
func WithRoles(ctx httpx.IRequestContext, roles []string) httpx.IRequestContext {
	return auth.WithRoles(ctx, roles)
}

// WithPermissions 将权限列表写入请求上下文。
func WithPermissions(ctx httpx.IRequestContext, permissions []string) httpx.IRequestContext {
	return auth.WithPermissions(ctx, permissions)
}

// AuthConfig 认证配置（兼容：旧 import path）
type AuthConfig = iammw.AuthConfig

// DefaultAuthConfig 默认认证配置
func DefaultAuthConfig() *AuthConfig {
	return iammw.DefaultAuthConfig()
}

// JWTClaims JWT 声明（兼容：旧 import path）
type JWTClaims = iammw.JWTClaims

// GenerateToken 生成 JWT 访问令牌
func GenerateToken(userID int64, username string, roles, permissions []string, secretKey string) (string, error) {
	return iammw.GenerateToken(userID, username, roles, permissions, secretKey)
}

// RefreshToken 刷新 JWT 令牌
func RefreshToken(tokenString, secretKey string) (string, error) {
	return iammw.RefreshToken(tokenString, secretKey)
}

// AdminOnlyMiddleware 仅管理员中间件
func AdminOnlyMiddleware() httpx.Middleware {
	return iammw.AdminOnlyMiddleware()
}

// UserOnlyMiddleware 仅用户中间件（已认证用户）
func UserOnlyMiddleware() httpx.Middleware {
	return iammw.UserOnlyMiddleware()
}

// RoleMiddleware 角色验证中间件
func RoleMiddleware(requiredRole string) httpx.Middleware {
	return iammw.RoleMiddleware(requiredRole)
}

// RequireAnyRole 检查是否拥有任一指定角色
func RequireAnyRole(ctx httpx.IRequestContext, roles ...string) error {
	return iammw.RequireAnyRole(ctx, roles...)
}

// RequirePermission 检查是否拥有指定权限
func RequirePermission(ctx httpx.IRequestContext, permission string) error {
	return iammw.RequirePermission(ctx, permission)
}

// PermissionMiddleware 权限验证中间件
func PermissionMiddleware(requiredPermission string) httpx.Middleware {
	return iammw.PermissionMiddleware(requiredPermission)
}

// GetRoles 从请求上下文获取角色列表
func GetRoles(ctx httpx.IRequestContext) []string {
	return auth.GetRoles(ctx)
}

// GetPermissions 从请求上下文获取权限列表
func GetPermissions(ctx httpx.IRequestContext) []string {
	return auth.GetPermissions(ctx)
}
