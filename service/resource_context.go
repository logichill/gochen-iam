package service

import (
	"context"
	"strings"

	"gochen/authz"
	"gochen/domain"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

// LoadTenantBoundResource 先解析目标资源边界，再绑定 tenant/scope runtime，最后在统一 tenantCtx 中读取实体。
//
// 这样 service 层不需要再先用旧 ctx 读一跳、再手工切 tenantCtx。
func LoadTenantBoundResource[T domain.IEntity[ID], ID comparable](
	ctx context.Context,
	repo domaincrud.IResourceBoundaryRepository[T, ID],
	id ID,
) (T, context.Context, error) {
	var zero T
	if repo == nil {
		return zero, nil, errorx.New(errorx.InvalidInput, "repo is required")
	}
	resource, err := repo.ResolveResourceByID(ctx, id)
	if err != nil {
		return zero, nil, err
	}

	boundCtx, err := BindResourceContext(ctx, resource)
	if err != nil {
		return zero, nil, err
	}

	entity, err := repo.Get(boundCtx, id)
	if err != nil {
		return zero, nil, err
	}
	return entity, boundCtx, nil
}

// BindResourceContext 把资源解析出的 tenant/scope 边界绑定回上下文。
//
// 说明：
//   - tenant 维度仍复用 BindTenantContext(...) 统一处理 principal/contextx 对齐；
//   - scope 维度只通过显式 DataScope 回写，确保 repo/GetWith/FindOneWith 按“资源本身的边界”读取，
//     而不是继续沿用调用方原始 scoped runtime。
func BindResourceContext(ctx context.Context, resource authz.Resource) (context.Context, error) {
	resource.TenantID = strings.TrimSpace(resource.TenantID)
	resource.ScopeType = strings.TrimSpace(resource.ScopeType)
	resource.ScopeCode = strings.TrimSpace(resource.ScopeCode)

	boundCtx := ctx
	var err error
	if resource.TenantID != "" {
		boundCtx, err = BindTenantContext(ctx, resource.TenantID)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case resource.TenantID == "" && resource.ScopeType == "" && resource.ScopeCode == "":
		return boundCtx, nil
	case resource.ScopeType != "" || resource.ScopeCode != "":
		return authz.WithDataScope(boundCtx, authz.DataScope{
			TenantID:  resource.TenantID,
			ScopeType: resource.ScopeType,
			ScopeCode: resource.ScopeCode,
			Mode:      authz.ScopeModeScoped,
		})
	default:
		return authz.WithDataScope(boundCtx, authz.DataScope{
			TenantID: resource.TenantID,
			Mode:     authz.ScopeModeTenant,
		})
	}
}
