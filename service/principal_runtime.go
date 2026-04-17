package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	"gochen/authz"
	"gochen/errorx"
)

func principalFromContext(ctx context.Context) (authz.Principal, bool) {
	if principal, ok := authz.PrincipalFromContext(ctx); ok {
		return principal.Clone(), true
	}
	return authz.Principal{}, false
}

func activeScopeIDFromContext(ctx context.Context) int64 {
	if scopeID := iamauth.ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scopeID
	}
	if principal, ok := principalFromContext(ctx); ok && principal.ActiveScopeID > 0 {
		return principal.ActiveScopeID
	}
	return 0
}

func activeScopeKindFromContext(ctx context.Context) string {
	return iamauth.ActiveScopeKindFromContext(ctx)
}

func requirePrincipalPermission(ctx context.Context, permission string) error {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return nil
	}
	principal, err := authz.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if principalHasPermission(principal, permission) {
		return nil
	}
	return errorx.New(errorx.Forbidden, "权限不足")
}

func principalHasPermission(principal authz.Principal, permission string) bool {
	return principal.AllowsPermission(strings.TrimSpace(permission))
}

func principalCanAccessPlatform(principal authz.Principal, ctx context.Context) bool {
	if principal.IsSystem {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(activeScopeKindFromContext(ctx)), string(iammw.ScopePlatform))
}
