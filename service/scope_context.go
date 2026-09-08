package service

import (
	"context"

	iamauth "gochen-iam/auth"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
)

// BindManagedScopeContext 将单一 managed scope 绑定回上下文，供 repo 查询/写入统一消费。
func BindManagedScopeContext(ctx context.Context, managedScopeID int64) (context.Context, error) {
	return BindVisibleScopeContext(ctx, managedScopeID, []int64{managedScopeID})
}

// BindVisibleScopeContext 将 active scope 与可见范围集合一起绑定回上下文。
func BindVisibleScopeContext(ctx context.Context, activeScopeID int64, visibleScopeIDs []int64) (context.Context, error) {
	if activeScopeID <= 0 {
		return ctx, nil
	}
	scopeKind := ""
	if iamauth.ActiveScopeIDFromContext(ctx) == activeScopeID {
		scopeKind = iamauth.ActiveScopeKindFromContext(ctx)
	}
	boundCtx := iamauth.ClearActiveScopeContext(ctx)
	boundCtx = iamauth.BindActiveScopeContext(boundCtx, activeScopeID, scopeKind)
	var err error
	boundCtx, err = rebindPrincipalActiveScope(boundCtx, activeScopeID)
	if err != nil {
		return nil, err
	}
	return scoped.WithDataScope(boundCtx, scoped.Filtered(visibleScopeIDs...))
}

func rebindPrincipalActiveScope(ctx context.Context, activeScopeID int64) (context.Context, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || principal.ActiveScopeID == activeScopeID {
		return ctx, nil
	}

	tenantID := contextx.TenantID(ctx)
	principal.ActiveScopeID = activeScopeID

	boundCtx, err := auth.WithPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	if tenantID == "" || contextx.TenantID(boundCtx) == tenantID {
		return boundCtx, nil
	}
	return contextx.WithTenantID(boundCtx, tenantID)
}
