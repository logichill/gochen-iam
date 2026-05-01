package middleware

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	auth "gochen/auth"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
)

// PrincipalFromClaims 将 JWT claims 映射为共享授权 Principal。
func PrincipalFromClaims(claims *JWTClaims, tenantID string) auth.Principal {
	if claims == nil {
		return auth.Principal{}
	}
	_ = strings.TrimSpace(tenantID)
	return auth.Principal{
		SubjectID:     claims.UserID,
		Permissions:   claims.Permissions,
		ActiveScopeID: claims.ActiveScopeID,
	}
}

// InjectClaimsRequestContext 将 claims 统一写入 request context。
func InjectClaimsRequestContext(
	reqCtx httpx.IRequestContext,
	tenantID string,
	claims *JWTClaims,
	resolver AuthContextResolver,
) (httpx.IRequestContext, error) {
	if reqCtx == nil {
		return nil, errors.NewCode(errors.InvalidInput, "request context is nil")
	}
	if claims == nil {
		return nil, errors.NewCode(errors.InvalidInput, "claims are required")
	}

	baseCtx := context.Context(reqCtx)
	var err error
	var runtime *ResolvedAuthContext
	if claims.UserID > 0 {
		baseCtx, err = contextx.WithUserID(baseCtx, claims.UserID)
		if err != nil {
			return nil, err
		}
	}
	baseCtx = iamauth.BindActiveScopeContext(baseCtx, claims.ActiveScopeID, "")
	if claims.ActiveScopeID > 0 {
		if resolver == nil {
			return nil, errors.NewCode(errors.InvalidInput, "auth context resolver is required")
		}
		runtime, err = resolver.ResolveAuthContext(baseCtx, claims)
		if err != nil {
			return nil, err
		}
		if runtime == nil {
			return nil, errors.NewCode(errors.InvalidInput, "resolved auth context is required")
		}
		baseCtx = iamauth.BindActiveScopeContext(baseCtx, runtime.ActiveScopeID, runtime.ActiveScopeKind)
		baseCtx, err = auth.WithDataScope(baseCtx, auth.DataScope{
			ActiveScopeID:   runtime.ActiveScopeID,
			VisibleScopeIDs: runtime.VisibleScopeIDs,
			Mode:            auth.ScopeModeManagedScopes,
		})
		if err != nil {
			return nil, err
		}
	}
	baseCtx, err = auth.WithPrincipal(baseCtx, PrincipalFromClaims(claims, tenantID))
	if err != nil {
		return nil, err
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		baseCtx, err = contextx.WithTenantID(baseCtx, tenantID)
		if err != nil {
			return nil, err
		}
	}

	bound := reqCtx.WithContext(baseCtx)
	bound = iamauth.WithPermissions(bound, claims.Permissions)
	if claims.ActiveScopeID > 0 {
		bound = iamauth.WithActiveScope(bound, runtime.ActiveScopeID, runtime.ActiveScopeKind)
	}
	return bound, nil
}
