package service

import (
	"context"
	"strings"

	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	"gochen/errorx"
)

type tenantAccessResolution struct {
	TenantID       string
	SkipScopeCheck bool
}

// resolveTenantAccess 收敛 tenant 维度访问语义：
// - fixed 模式：tenant 退化为常量，并跳过 scope coverage 计算；
// - platform active scope：允许显式 target tenant 覆盖当前 tenant；
// - 其他模式：保持当前 same-tenant 约束。
func resolveTenantAccess(ctx context.Context, targetTenantID string) (tenantAccessResolution, error) {
	targetTenantID = strings.TrimSpace(targetTenantID)

	if tenant.Current().IsSingle() {
		tenantID, err := tenant.NormalizeTenantID(ctx, targetTenantID)
		if err != nil {
			return tenantAccessResolution{}, err
		}
		return tenantAccessResolution{
			TenantID:       tenantID,
			SkipScopeCheck: true,
		}, nil
	}

	if strings.EqualFold(activeScopeKindFromContext(ctx), string(iammw.ScopePlatform)) {
		if targetTenantID == "" {
			tenantID, err := TenantIDFromContext(ctx)
			if err != nil {
				return tenantAccessResolution{}, err
			}
			return tenantAccessResolution{TenantID: tenantID}, nil
		}
		return tenantAccessResolution{TenantID: targetTenantID}, nil
	}

	tenantID, err := tenant.NormalizeTenantID(ctx, targetTenantID)
	if err != nil {
		return tenantAccessResolution{}, err
	}

	currentTenantID, err := TenantIDFromContext(ctx)
	if err != nil {
		return tenantAccessResolution{}, err
	}
	if currentTenantID != tenantID {
		return tenantAccessResolution{}, errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}

	return tenantAccessResolution{TenantID: tenantID}, nil
}
