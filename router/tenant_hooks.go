package router

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	appcrud "gochen/app/crud"
	"gochen/domain"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

type platformTenantFinder interface {
	FindPlatform(ctx context.Context) (*iamentity.Tenant, error)
}

// TenantHooksForUser 创建用户租户隔离钩子。
func TenantHooksForUser(repo domaincrud.IRepository[*iamentity.User, int64]) *appcrud.Hooks[*iamentity.User, int64] {
	return &appcrud.Hooks[*iamentity.User, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.User) error {
			tenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			entity.SetTenantID(tenantID)
			return nil
		},
		BeforeUpdate: func(ctx context.Context, entity *iamentity.User) error {
			contextTenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			if entity != nil && entity.GetID() > 0 && entity.GetTenantID() == "" {
				current, err := repo.Get(ctx, entity.GetID())
				if err != nil {
					return err
				}
				entity.SetTenantID(current.GetTenantID())
			}
			if entity.GetTenantID() != contextTenantID {
				return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
			}
			return nil
		},
		BeforeDelete: func(ctx context.Context, id int64) error {
			return checkTenantOwnership(ctx, repo, id)
		},
	}
}

// TenantHooksForRole 创建角色租户隔离钩子。
func TenantHooksForRole(
	repo domaincrud.IRepository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
) *appcrud.Hooks[*iamentity.Role, int64] {
	return &appcrud.Hooks[*iamentity.Role, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.Role) error {
			tenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			entity.SetTenantID(tenantID)
			if scopeAuthorizer != nil {
				namespaceScope, err := scopeAuthorizer.ResolveTenantScope(ctx, tenantID)
				if err != nil {
					return err
				}
				entity.NamespaceScopeID = namespaceScope.ID
			}
			return nil
		},
		BeforeUpdate: func(ctx context.Context, entity *iamentity.Role) error {
			contextTenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			if entity != nil && entity.GetID() > 0 {
				current, err := repo.Get(ctx, entity.GetID())
				if err != nil {
					return err
				}
				entity.SetTenantID(current.GetTenantID())
				if entity.NamespaceScopeID <= 0 {
					entity.NamespaceScopeID = current.NamespaceScopeID
				}
			}
			if entity.GetTenantID() != contextTenantID {
				return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
			}
			return nil
		},
		BeforeDelete: func(ctx context.Context, id int64) error {
			return checkTenantOwnership(ctx, repo, id)
		},
	}
}

// TenantHooksForTenant 在创建 tenant 时自动补齐 root scope。
func TenantHooksForTenant(
	repo domaincrud.IRepository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
) *appcrud.Hooks[*iamentity.Tenant, int64] {
	return &appcrud.Hooks[*iamentity.Tenant, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.Tenant) error {
			if entity == nil {
				return nil
			}
			entity.RootScopeID = nil
			entity.SyncPlatformSlot()
			if entity.IsPlatform {
				if finder, ok := repo.(platformTenantFinder); ok && finder != nil {
					existing, err := finder.FindPlatform(ctx)
					if err == nil && existing != nil {
						return errorx.New(errorx.Validation, "平台租户已存在")
					}
					if err != nil && !errorx.Is(err, errorx.NotFound) {
						return err
					}
				}
			}
			return nil
		},
		AfterCreate: func(ctx context.Context, entity *iamentity.Tenant) error {
			if entity == nil || scopeAuthorizer == nil {
				return nil
			}
			_, err := scopeAuthorizer.EnsureTenantRootScope(ctx, entity)
			return err
		},
		BeforeUpdate: func(ctx context.Context, entity *iamentity.Tenant) error {
			if entity == nil || entity.GetID() <= 0 {
				return nil
			}
			current, err := repo.Get(ctx, entity.GetID())
			if err != nil {
				return err
			}
			entity.RootScopeID = current.RootScopeID
			entity.IsPlatform = current.IsPlatform
			entity.PlatformSlot = current.PlatformSlot
			return nil
		},
	}
}

func newScopeBackedRoleCRUDHooks(
	repo domaincrud.IRepository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
) *appcrud.Hooks[*iamentity.Role, int64] {
	return TenantHooksForRole(repo, scopeAuthorizer)
}

func newTenantCRUDHooks(
	repo domaincrud.IRepository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
) *appcrud.Hooks[*iamentity.Tenant, int64] {
	return TenantHooksForTenant(repo, scopeAuthorizer)
}

// tenantOwner 是拥有 tenant_id 的实体的通用接口。
type tenantOwner[ID comparable] interface {
	domain.IEntity[ID]
	GetTenantID() string
}

// checkTenantOwnership 通用的删除前租户校验：获取实体并比对 tenant_id。
func checkTenantOwnership[T tenantOwner[ID], ID comparable](ctx context.Context, repo domaincrud.IRepository[T, ID], id ID) error {
	contextTenantID, err := domaincrud.ResolveTenantID(ctx)
	if err != nil {
		return err
	}
	entity, err := repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if entity.GetTenantID() != contextTenantID {
		return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}
	return nil
}
