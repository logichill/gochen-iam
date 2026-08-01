package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	auth "gochen/auth"
	"gochen/domain"
	"gochen/domain/access"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
)

// IResourceContextRepository 组合了资源边界解析与基础按 ID 读取能力。
type IResourceContextRepository[T domain.IEntity[ID], ID comparable] interface {
	domaincrud.IRepository[T, ID]
	access.IResourceBoundaryRepository[T, ID]
}

// IScopedResourceContextRepository 组合了资源上下文读能力与显式写约束能力。
type IScopedResourceContextRepository[T domain.IEntity[ID], ID comparable] interface {
	IResourceContextRepository[T, ID]
	domaincrud.IQueryRepository[T, ID]
	IScopedConstraintRepository[T, ID]
}

// LoadTenantBoundResource 先解析目标资源边界，再绑定 runtime，最后在统一上下文中读取实体。
func LoadTenantBoundResource[T domain.IEntity[ID], ID comparable](
	ctx context.Context,
	repo IResourceContextRepository[T, ID],
	id ID,
) (T, context.Context, error) {
	var zero T
	if repo == nil {
		return zero, nil, errors.NewCode(errors.InvalidInput, "repo is required")
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

// BindResourceContext 把资源解析出的边界绑定回上下文。
func BindResourceContext(ctx context.Context, resource access.ResourceBoundary) (context.Context, error) {
	boundCtx := ctx
	if tenantID := tenantIDFromBoundary(resource); tenantID != "" {
		var err error
		boundCtx, err = BindTenantContext(boundCtx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	if resource.ManagedScopeID <= 0 {
		return clearBoundScopeContext(boundCtx)
	}
	return BindVisibleScopeContext(boundCtx, resource.ManagedScopeID, []int64{resource.ManagedScopeID})
}

func tenantIDFromBoundary(resource access.ResourceBoundary) string {
	if tenantID := strings.TrimSpace(resource.TenantID); tenantID != "" {
		return tenantID
	}
	ownerID := strings.TrimSpace(resource.OwnerID)
	if strings.HasPrefix(ownerID, tenantOwnerPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(ownerID, tenantOwnerPrefix))
	}
	return ""
}

func clearBoundScopeContext(ctx context.Context) (context.Context, error) {
	boundCtx := iamauth.ClearActiveScopeContext(ctx)
	var err error
	boundCtx, err = rebindPrincipalActiveScope(boundCtx, 0)
	if err != nil {
		return nil, err
	}
	if scope, ok := auth.DataScopeFromContext(boundCtx); ok && scope.Mode == auth.ScopeModeScoped {
		return auth.WithDataScope(boundCtx, auth.DataScope{Mode: auth.ScopeModeGlobal})
	}
	return boundCtx, nil
}

// BindTenantGlobalScopeContext 在保留 tenant 边界的同时清空 managed scope 约束。
// 适用于需要判断“资源真实存在”与“当前 scope 不可见”差异的场景。
func BindTenantGlobalScopeContext(ctx context.Context, tenantID string) (context.Context, error) {
	tenantCtx, err := BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return clearBoundScopeContext(tenantCtx)
}
