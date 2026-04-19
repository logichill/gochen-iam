package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	"gochen/auth"
	"gochen/contextx"
	"gochen/errors"
)

// BindTenantContext 将已归一化/已校验通过的 tenant 绑定回上下文。
func BindTenantContext(ctx context.Context, tenantID string) (context.Context, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.NewCode(errors.Validation, "tenant_id is required")
	}
	currentTenantID := strings.TrimSpace(contextx.TenantID(ctx))
	if currentTenantID == "" || currentTenantID == tenantID {
		derived, err := contextx.WithTenantID(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		return ensureTenantReadScope(derived)
	}

	derived := iamauth.ClearActiveScopeContext(ctx)
	var err error
	// 租户切换后，旧 active scope / data scope 都不再可信，避免把前一个租户的边界带入新上下文。
	if principal, ok := auth.PrincipalFromContext(ctx); ok && principal.ActiveScopeID != 0 {
		principal.ActiveScopeID = 0
		derived, err = auth.WithPrincipal(derived, principal)
		if err != nil {
			return nil, err
		}
	}
	if scope, ok := auth.DataScopeFromContext(derived); ok && scope.Mode == auth.ScopeModeManagedScopes {
		derived, err = auth.WithDataScope(derived, auth.DataScope{Mode: auth.ScopeModeGlobal})
		if err != nil {
			return nil, err
		}
	}
	derived, err = contextx.WithTenantID(derived, tenantID)
	if err != nil {
		return nil, err
	}
	return ensureTenantReadScope(derived)
}

func ensureTenantReadScope(ctx context.Context) (context.Context, error) {
	if _, ok := auth.DataScopeFromContext(ctx); ok {
		return ctx, nil
	}
	return auth.WithDataScope(ctx, auth.DataScope{Mode: auth.ScopeModeGlobal})
}
