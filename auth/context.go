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
	return ctx.WithContext(authz.BindActiveScopeContext(ctx, scopeID, scopeKind))
}

// BindActiveScopeContext 将 active scope 元数据写入通用 context，便于 service/runtime 读取。
func BindActiveScopeContext(ctx context.Context, scopeID int64, scopeKind string) context.Context {
	return authz.BindActiveScopeContext(ctx, scopeID, scopeKind)
}

// ClearActiveScopeContext 清空通用 context 上的 active scope 元数据。
func ClearActiveScopeContext(ctx context.Context) context.Context {
	return authz.ClearActiveScopeContext(ctx)
}

func ActiveScopeID(ctx httpx.IRequestContext) int64 {
	return authz.ActiveScopeIDFromContext(ctx)
}

func ActiveScopeKind(ctx httpx.IRequestContext) string {
	return authz.ActiveScopeKindFromContext(ctx)
}

func ActiveScopeIDFromContext(ctx context.Context) int64 {
	return authz.ActiveScopeIDFromContext(ctx)
}

func ActiveScopeKindFromContext(ctx context.Context) string {
	return authz.ActiveScopeKindFromContext(ctx)
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
