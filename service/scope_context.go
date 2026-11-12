package service

import (
	"context"

	iamauth "gochen-iam/auth"
	coreauth "gochen/auth"
	"gochen/auth/scoped"
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
	if currentScopeID := iamauth.ActiveScopeIDFromContext(ctx); currentScopeID == activeScopeID || (currentScopeID == 0 && iamauth.ResolveManagedScopeID(ctx) == activeScopeID) {
		scopeKind = iamauth.ActiveScopeKindFromContext(ctx)
	}
	boundCtx := iamauth.ClearActiveScopeContext(ctx)
	var err error
	boundCtx, err = rebindPrincipalActiveScope(boundCtx, activeScopeID)
	if err != nil {
		return nil, err
	}
	boundCtx = iamauth.BindActiveScopeContext(boundCtx, activeScopeID, scopeKind)
	return scoped.WithDataScope(boundCtx, scoped.Filtered(visibleScopeIDs...))
}

func rebindPrincipalActiveScope(ctx context.Context, activeScopeID int64) (context.Context, error) {
	principal, ok := coreauth.PrincipalFromContext(ctx)
	if !ok || principal.ScopeID == activeScopeID {
		return ctx, nil
	}

	principal.ScopeID = activeScopeID
	// 范围绑定只更新身份；新范围的权限资料由可信认证入口建立。
	return coreauth.WithPrincipal(ctx, principal)
}
