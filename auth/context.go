package auth

import (
	"context"
	"strings"

	"gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/httpx"
)

type contextKey string

const (
	contextKeyRoles           contextKey = "auth_roles"
	contextKeyPermissions     contextKey = "auth_permissions"
	contextKeyPermSet         contextKey = "auth_permission_set"
	contextKeyActiveScopeID   contextKey = "auth_active_scope_id"
	contextKeyActiveScopeKind contextKey = "auth_active_scope_kind"
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
func WithActiveScope(ctx httpx.IRequestContext, scopeID int64, scopeKind string) httpx.IRequestContext {
	if ctx == nil {
		return nil
	}
	if scopeID > 0 {
		ctx = ctx.WithValue(contextKeyActiveScopeID, scopeID)
	}
	if scopeKind != "" {
		ctx = ctx.WithValue(contextKeyActiveScopeKind, scopeKind)
	}
	return ctx
}

// BindActiveScopeContext 将 active scope 元数据写入通用 context，便于 service/runtime 读取。
func BindActiveScopeContext(ctx context.Context, scopeID int64, scopeKind string) context.Context {
	if ctx == nil {
		return nil
	}
	if scopeID > 0 {
		ctx = context.WithValue(ctx, contextKeyActiveScopeID, scopeID)
	}
	if scopeKind = strings.TrimSpace(scopeKind); scopeKind != "" {
		ctx = context.WithValue(ctx, contextKeyActiveScopeKind, scopeKind)
	}
	return ctx
}

// ClearActiveScopeContext 清空通用 context 上的 active scope 元数据。
func ClearActiveScopeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	ctx = context.WithValue(ctx, contextKeyActiveScopeID, int64(0))
	ctx = context.WithValue(ctx, contextKeyActiveScopeKind, "")
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

func ActiveScopeKind(ctx httpx.IRequestContext) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(contextKeyActiveScopeKind); val != nil {
		if scopeKind, ok := val.(string); ok {
			return scopeKind
		}
	}
	return ""
}

func ActiveScopeIDFromContext(ctx context.Context) int64 {
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

func ActiveScopeKindFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Value(contextKeyActiveScopeKind); val != nil {
		if scopeKind, ok := val.(string); ok {
			return strings.TrimSpace(scopeKind)
		}
	}
	return ""
}

// DefaultDataScopeResolver 为 IAM 仓储、服务与路由提供统一默认数据范围解析。
var DefaultDataScopeResolver = scoped.DataScopeResolverFunc(func(ctx context.Context) (scoped.DataScope, error) {
	if scope, ok := scoped.DataScopeFromContext(ctx); ok {
		return scope, nil
	}
	if principal, ok := authz.PrincipalFromContext(ctx); ok {
		if principal.IsSystem {
			return scoped.Global(), nil
		}
		if principal.ActiveScopeID > 0 {
			return scoped.Filtered(principal.ActiveScopeID), nil
		}
	}
	if scopeID := ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scoped.Filtered(scopeID), nil
	}
	return scoped.DenyAll(), nil
})

// ResolveManagedScopeID 解析用于受管范围写入的 scope ID。
func ResolveManagedScopeID(ctx context.Context) int64 {
	if scopeID := ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scopeID
	}
	if scope, ok := scoped.DataScopeFromContext(ctx); ok {
		if len(scope.ScopeIDs) == 1 {
			return scope.ScopeIDs[0]
		}
	}
	if principal, ok := authz.PrincipalFromContext(ctx); ok && principal.ActiveScopeID > 0 {
		return principal.ActiveScopeID
	}
	return 0
}
