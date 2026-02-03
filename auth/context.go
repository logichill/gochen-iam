package auth

import (
	"strings"

	"gochen/httpx"
)

type contextKey string

const (
	contextKeyRoles       contextKey = "auth_roles"
	contextKeyPermissions contextKey = "auth_permissions"
	contextKeyPermSet     contextKey = "auth_permission_set"
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
	permSet := make(map[string]struct{}, len(permissions))
	for _, p := range permissions {
		if p == "" {
			continue
		}
		permSet[strings.ToLower(p)] = struct{}{}
	}
	ctx = ctx.WithValue(contextKeyPermissions, permissions)
	ctx = ctx.WithValue(contextKeyPermSet, permSet)
	return ctx
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

// GetPermissionSet 从请求上下文获取权限集合（用于 O(1) 判断）。
// 若未注入集合，返回 nil（调用方可回退到 GetPermissions 做线性判断）。
func GetPermissionSet(ctx httpx.IRequestContext) map[string]struct{} {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(contextKeyPermSet); val != nil {
		if set, ok := val.(map[string]struct{}); ok {
			return set
		}
	}
	return nil
}
