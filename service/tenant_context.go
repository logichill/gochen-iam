package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/errorx"
)

// BindTenantContext 将已归一化/已校验通过的 tenant 绑定回上下文。
func BindTenantContext(ctx context.Context, tenantID string) (context.Context, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errorx.New(errorx.Validation, "tenant_id is required")
	}
	currentTenantID := strings.TrimSpace(ctxx.TenantID(ctx))
	if currentTenantID == "" || currentTenantID == tenantID {
		derived, err := ctxx.WithTenantID(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		return ensureTenantReadScope(derived)
	}

	derived := iamauth.ClearActiveScopeContext(ctx)
	var err error
	// 租户切换后，旧 active scope / data scope 都不再可信，避免把前一个租户的边界带入新上下文。
	if principal, ok := authz.PrincipalFromContext(ctx); ok && principal.ActiveScopeID != 0 {
		principal.ActiveScopeID = 0
		derived, err = authz.WithPrincipal(derived, principal)
		if err != nil {
			return nil, err
		}
	}
	if scope, ok := authz.DataScopeFromContext(derived); ok && scope.Mode == authz.ScopeModeManagedScopes {
		derived, err = authz.WithDataScope(derived, authz.DataScope{Mode: authz.ScopeModeGlobal})
		if err != nil {
			return nil, err
		}
	}
	derived, err = ctxx.WithTenantID(derived, tenantID)
	if err != nil {
		return nil, err
	}
	return ensureTenantReadScope(derived)
}

func ensureTenantReadScope(ctx context.Context) (context.Context, error) {
	if _, ok := authz.DataScopeFromContext(ctx); ok {
		return ctx, nil
	}
	return authz.WithDataScope(ctx, authz.DataScope{Mode: authz.ScopeModeGlobal})
}
