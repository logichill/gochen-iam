package service

import (
	"context"
	"strings"

	iammw "gochen-iam/middleware"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/errorx"
)

// BindTenantContext 将已归一化/已校验通过的 tenant 绑定回上下文，
// 让 repo 层统一从 principal/DataScope 推导可见性边界，而不是再显式接收 tenant 参数。
func BindTenantContext(ctx context.Context, tenantID string) (context.Context, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errorx.New(errorx.Validation, "tenant_id is required")
	}

	derived, err := ctxx.WithTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	resetPlatformScope := false
	if principal, ok := authz.PrincipalFromContext(ctx); ok {
		principal.TenantID = tenantID
		if shouldDropPlatformScopeForTenantBinding(principal) {
			principal.ActiveScopeID = 0
			principal.ActiveScopeType = ""
			principal.ActiveScopeCode = ""
			resetPlatformScope = true
		}
		derived, err = authz.WithPrincipal(derived, principal)
		if err != nil {
			return nil, err
		}
	}

	if scope, ok := authz.DataScopeFromContext(ctx); ok {
		scope.TenantID = tenantID
		if resetPlatformScope || shouldDropPlatformDataScope(scope) {
			scope.ScopeType = ""
			scope.ScopeCode = ""
			scope.ScopeCodes = nil
			scope.Mode = authz.ScopeModeTenant
		} else if scope.Mode == authz.ScopeModeGlobal {
			scope.Mode = authz.ScopeModeTenant
		}
		derived, err = authz.WithDataScope(derived, scope)
		if err != nil {
			return nil, err
		}
	}

	return derived, nil
}

func shouldDropPlatformScopeForTenantBinding(principal authz.Principal) bool {
	return strings.EqualFold(strings.TrimSpace(principal.ActiveScopeType), string(iammw.ScopePlatform)) ||
		strings.EqualFold(strings.TrimSpace(principal.ActiveScopeCode), platformScopeCode)
}

func shouldDropPlatformDataScope(scope authz.DataScope) bool {
	return strings.EqualFold(strings.TrimSpace(scope.ScopeType), string(iammw.ScopePlatform)) ||
		strings.EqualFold(strings.TrimSpace(scope.ScopeCode), platformScopeCode)
}
