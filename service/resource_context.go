package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	"gochen/auth/scoped"
	"gochen/domain"
	domaincrud "gochen/domain/crud"
	"gochen/domain/spec"
	"gochen/errors"
)

// IResourceContextRepository 提供按 ID 读取目标资源的能力。
type IResourceContextRepository[T domain.IEntity[ID], ID comparable] interface {
	domaincrud.IRepository[T, ID]
}

// LoadTenantBoundResource 读取目标资源，并把资源所属 tenant 绑定回上下文。
//
// 读取仍受仓储 tenant 隔离保护；行级可见性由调用方随后的显式授权与写规约负责，
// 因此这里使用 spec.All()，不把调用方的数据范围伪装成目标资源边界。
func LoadTenantBoundResource[T domain.IEntity[ID], ID comparable](
	ctx context.Context,
	repo IResourceContextRepository[T, ID],
	id ID,
) (T, context.Context, error) {
	var zero T
	if repo == nil {
		return zero, nil, errors.NewCode(errors.InvalidInput, "repo is required")
	}
	entity, err := repo.Get(ctx, id, spec.All())
	if err != nil {
		return zero, nil, err
	}

	boundCtx := ctx
	if source, ok := any(entity).(interface{ GetTenantID() string }); ok {
		if tenantID := strings.TrimSpace(source.GetTenantID()); tenantID != "" {
			boundCtx, err = BindTenantContext(boundCtx, tenantID)
			if err != nil {
				return zero, nil, err
			}
		}
	}
	return entity, boundCtx, nil
}

func clearBoundScopeContext(ctx context.Context) (context.Context, error) {
	boundCtx := iamauth.ClearActiveScopeContext(ctx)
	var err error
	boundCtx, err = rebindPrincipalActiveScope(boundCtx, 0)
	if err != nil {
		return nil, err
	}
	if scope, ok := scoped.DataScopeFromContext(boundCtx); ok && scope.Kind == scoped.ScopeFiltered {
		return scoped.WithDataScope(boundCtx, scoped.Global())
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
