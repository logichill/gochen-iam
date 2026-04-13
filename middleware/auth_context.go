package middleware

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/errorx"
	"gochen/httpx"
)

// PrincipalFromClaims 将 JWT claims 映射为共享授权 Principal。
func PrincipalFromClaims(claims *JWTClaims, tenantID string) authz.Principal {
	if claims == nil {
		return authz.Principal{}
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(claims.TenantID)
	}
	return authz.Principal{
		SubjectID:       claims.UserID,
		TenantID:        tenantID,
		Roles:           claims.Roles,
		Permissions:     claims.Permissions,
		ActiveScopeID:   claims.ActiveScopeID,
		ActiveScopeCode: claims.ActiveScopeCode,
		ActiveScopeType: claims.ActiveScopeType,
	}
}

// InjectClaimsRequestContext 将 claims 统一写入 request context。
func InjectClaimsRequestContext(reqCtx httpx.IRequestContext, tenantID string, claims *JWTClaims) (httpx.IRequestContext, error) {
	if reqCtx == nil {
		return nil, errorx.New(errorx.InvalidInput, "request context is nil")
	}
	if claims == nil {
		return nil, errorx.New(errorx.InvalidInput, "claims are required")
	}

	baseCtx := context.Context(reqCtx)
	var err error
	if claims.UserID > 0 {
		baseCtx, err = ctxx.WithUserID(baseCtx, claims.UserID)
		if err != nil {
			return nil, err
		}
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		baseCtx, err = ctxx.WithTenantID(baseCtx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	baseCtx, err = authz.WithPrincipal(baseCtx, PrincipalFromClaims(claims, tenantID))
	if err != nil {
		return nil, err
	}

	bound := reqCtx.WithContext(baseCtx)
	bound = iamauth.WithRoles(bound, claims.Roles)
	bound = iamauth.WithPermissions(bound, claims.Permissions)
	principal, _ := authz.PrincipalFromContext(baseCtx)
	bound = iamauth.WithActiveScope(bound, principal.ActiveScopeID, principal.ActiveScopeCode, principal.ActiveScopeType)
	return bound, nil
}
