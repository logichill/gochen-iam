package authctx

import (
	httpx "gochen/httpx"
)

type contextKey string

const (
	contextKeyRoles       contextKey = "auth_roles"
	contextKeyPermissions contextKey = "auth_permissions"
)

// WithRoles 将角色列表写入请求上下文。
func WithRoles(ctx httpx.IRequestContext, roles []string) httpx.IRequestContext {
	if ctx == nil || len(roles) == 0 {
		return ctx
	}
	return ctx.WithValue(contextKeyRoles, roles)
}

// WithPermissions 将权限列表写入请求上下文。
func WithPermissions(ctx httpx.IRequestContext, permissions []string) httpx.IRequestContext {
	if ctx == nil || len(permissions) == 0 {
		return ctx
	}
	return ctx.WithValue(contextKeyPermissions, permissions)
}

// GetRoles 从请求上下文获取角色列表
func GetRoles(ctx httpx.IRequestContext) []string {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(contextKeyRoles); val != nil {
		if roles, ok := val.([]string); ok {
			return roles
		}
	}
	return nil
}

// GetPermissions 从请求上下文获取权限列表
func GetPermissions(ctx httpx.IRequestContext) []string {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(contextKeyPermissions); val != nil {
		if permissions, ok := val.([]string); ok {
			return permissions
		}
	}
	return nil
}

