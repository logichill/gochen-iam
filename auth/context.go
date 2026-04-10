package auth

import (
	"strings"

	"gochen/httpx"
)

type contextKey string

const (
	contextKeyRoles           contextKey = "auth_roles"
	contextKeyPermissions     contextKey = "auth_permissions"
	contextKeyPermSet         contextKey = "auth_permission_set"
	contextKeyActiveScopeID   contextKey = "auth_active_scope_id"
	contextKeyActiveScopeKey  contextKey = "auth_active_scope_key"
	contextKeyActiveScopeType contextKey = "auth_active_scope_type"
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

// Roles 从请求上下文获取角色列表
func Roles(ctx httpx.IRequestContext) []string {
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

// Permissions 从请求上下文获取权限列表
func Permissions(ctx httpx.IRequestContext) []string {
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

// PermissionSet 从请求上下文获取权限集合（用于 O(1) 判断）。
// 若未注入集合，返回 nil（调用方可回退到 Permissions 做线性判断）。
func PermissionSet(ctx httpx.IRequestContext) map[string]struct{} {
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

// WithActiveScope 将当前 token 生效的 active scope 写入请求上下文。
func WithActiveScope(ctx httpx.IRequestContext, scopeID int64, scopeKey, scopeType string) httpx.IRequestContext {
	if ctx == nil {
		return nil
	}
	if scopeID > 0 {
		ctx = ctx.WithValue(contextKeyActiveScopeID, scopeID)
	}
	if scopeKey != "" {
		ctx = ctx.WithValue(contextKeyActiveScopeKey, scopeKey)
	}
	if scopeType != "" {
		ctx = ctx.WithValue(contextKeyActiveScopeType, scopeType)
	}
	return ctx
}

func ActiveScopeID(ctx httpx.IRequestContext) int64 {
	if ctx == nil {
		return 0
	}
	if val := ctx.Value(contextKeyActiveScopeID); val != nil {
		if scopeID, ok := val.(int64); ok {
			return scopeID
		}
	}
	return 0
}

func ActiveScopeKey(ctx httpx.IRequestContext) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(contextKeyActiveScopeKey); val != nil {
		if scopeKey, ok := val.(string); ok {
			return scopeKey
		}
	}
	return ""
}

func ActiveScopeType(ctx httpx.IRequestContext) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(contextKeyActiveScopeType); val != nil {
		if scopeType, ok := val.(string); ok {
			return scopeType
		}
	}
	return ""
}
