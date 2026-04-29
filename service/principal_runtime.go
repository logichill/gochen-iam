package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	auth "gochen/auth/core"
	"gochen/errors"
)

func principalFromContext(ctx context.Context) (auth.Principal, bool) {
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		return principal.Clone(), true
	}
	return auth.Principal{}, false
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
	principal, err := auth.RequirePrincipal(ctx)
	if err != nil {
		return err
	}
	if principalHasPermission(principal, permission) {
		return nil
	}
	return errors.NewCode(errors.Forbidden, "权限不足")
}

func principalHasPermission(principal auth.Principal, permission string) bool {
	return principal.AllowsPermission(strings.TrimSpace(permission))
}

func principalCanAccessPlatform(principal auth.Principal, ctx context.Context) bool {
	if principal.IsSystem {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(activeScopeKindFromContext(ctx)), string(iammw.ScopePlatform))
}
