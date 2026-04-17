package service

import (
	"context"

	iammw "gochen-iam/middleware"
	"gochen/errorx"
)

// AuthContextResolver 将 access token claims 还原为运行时可消费的 scope 边界。
type AuthContextResolver struct {
	scopeAuthorizer *ScopeAuthorizer
}

// AuthContextResolverInstaller 仅用于把 resolver 注册进 middleware 运行时。
type AuthContextResolverInstaller struct{}

func NewAuthContextResolver(scopeAuthorizer *ScopeAuthorizer) *AuthContextResolver {
	resolver := &AuthContextResolver{scopeAuthorizer: scopeAuthorizer}
	iammw.InstallAuthContextResolver(resolver)
	return resolver
}

func (r *AuthContextResolver) ResolveAuthContext(ctx context.Context, claims *iammw.JWTClaims) (*iammw.ResolvedAuthContext, error) {
	if claims == nil || claims.ActiveScopeID <= 0 {
		return nil, errorx.New(errorx.Unauthorized, "active scope is required")
	}
	if r == nil || r.scopeAuthorizer == nil {
		return nil, errorx.New(errorx.InvalidInput, "scope authorizer is required")
	}
	scope, err := r.scopeAuthorizer.Scope(ctx, claims.ActiveScopeID)
	if err != nil {
		return nil, err
	}
	visibleScopeIDs, err := r.scopeAuthorizer.VisibleScopeIDs(ctx, claims.ActiveScopeID)
	if err != nil {
		return nil, err
	}
	return &iammw.ResolvedAuthContext{
		ActiveScopeID:   scope.ID,
		ActiveScopeKind: scope.Type,
		VisibleScopeIDs: visibleScopeIDs,
	}, nil
}

func InstallAuthContextResolver(resolver *AuthContextResolver) *AuthContextResolverInstaller {
	if resolver != nil {
		iammw.InstallAuthContextResolver(resolver)
	}
	return &AuthContextResolverInstaller{}
}
