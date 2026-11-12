package middleware

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
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
		SubjectID:     strconv.FormatInt(claims.UserID, 10),
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
	// ResolveAuthContext 需要在租户隔离仓储中读取用户与授权快照。
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		baseCtx, err = contextx.WithTenantID(baseCtx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	if claims.UserID > 0 {
		baseCtx, err = contextx.WithUserID(baseCtx, strconv.FormatInt(claims.UserID, 10))
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
	}
	principal := PrincipalFromClaims(claims, tenantID)
	if runtime != nil {
		principal.ActiveScopeID = runtime.ActiveScopeID
		principal.PermissionScopes = []string{runtime.ActiveScopeKind}
		// 显式单租户策略允许持有平台权限的用户管理本部署，与 IAM 平台入口一致。
		if tenant.CurrentContext(baseCtx).IsSingle() && !strings.EqualFold(runtime.ActiveScopeKind, string(auth.PermissionScopePlatform)) {
			principal.PermissionScopes = append(principal.PermissionScopes, string(auth.PermissionScopePlatform))
		}
	}
	baseCtx, err = auth.WithPrincipal(baseCtx, principal)
	if err != nil {
		return nil, err
	}
	if runtime != nil {
		baseCtx = iamauth.BindActiveScopeContext(baseCtx, runtime.ActiveScopeID, runtime.ActiveScopeKind)
		baseCtx, err = scoped.WithDataScope(baseCtx, scoped.Filtered(runtime.VisibleScopeIDs...))
		if err != nil {
			return nil, err
		}
	} else {
		baseCtx = iamauth.BindActiveScopeContext(baseCtx, principal.ActiveScopeID, "")
	}
	bound := reqCtx.WithContext(baseCtx)
	bound = iamauth.WithPermissions(bound, claims.Permissions)
	if claims.ActiveScopeID > 0 {
		bound = iamauth.WithActiveScope(bound, runtime.ActiveScopeID, runtime.ActiveScopeKind)
	}
	return bound, nil
}
