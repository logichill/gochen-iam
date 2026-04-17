package router

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	appcrud "gochen/app/crud"
	"gochen/domain"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

func loadTenantBoundEntity[T domain.IEntity[ID], ID comparable](
	ctx context.Context,
	repo svc.IResourceContextRepository[T, ID],
	id ID,
) (T, context.Context, error) {
	return svc.LoadTenantBoundResource(ctx, repo, id)
}

// TenantHooksForUser 创建用户租户隔离钩子。
func TenantHooksForUser(repo svc.IResourceContextRepository[*iamentity.User, int64]) *appcrud.Hooks[*iamentity.User, int64] {
	return &appcrud.Hooks[*iamentity.User, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.User) error {
			tenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			managedScopeID := svc.ManagedScopeIDFromContext(ctx)
			if managedScopeID <= 0 {
				return errorx.New(errorx.InvalidInput, "managed scope boundary is required")
			}
			entity.SetTenantID(tenantID)
			entity.SetHomeTenantID(tenantID)
			entity.SetHomeScopeID(managedScopeID)
			entity.SetManagedScopeID(managedScopeID)
			entity.SetOwnerID(svc.TenantOwnerID(tenantID))
			return nil
		},
		BeforeUpdate: func(ctx context.Context, entity *iamentity.User) error {
			contextTenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			if entity != nil && entity.GetID() > 0 && entity.GetTenantID() == "" {
				current, _, err := loadTenantBoundEntity(ctx, repo, entity.GetID())
				if err != nil {
					return err
				}
				entity.SetTenantID(current.GetTenantID())
				entity.SetHomeTenantID(current.GetHomeTenantID())
				entity.SetHomeScopeID(current.GetHomeScopeID())
				entity.SetManagedScopeID(current.GetManagedScopeID())
				entity.SetOwnerID(current.GetOwnerID())
			}
			if entity.GetTenantID() != contextTenantID {
				return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
			}
			if entity.GetHomeTenantID() == "" {
				entity.SetHomeTenantID(contextTenantID)
			}
			if entity.GetHomeScopeID() <= 0 {
				if managedScopeID := svc.ManagedScopeIDFromContext(ctx); managedScopeID > 0 {
					entity.SetHomeScopeID(managedScopeID)
				}
			}
			if entity.GetManagedScopeID() <= 0 {
				if current, _, err := loadTenantBoundEntity(ctx, repo, entity.GetID()); err == nil {
					entity.SetManagedScopeID(current.GetManagedScopeID())
				}
			}
			if entity.GetOwnerID() == "" {
				entity.SetOwnerID(svc.TenantOwnerID(contextTenantID))
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
	repo svc.IResourceContextRepository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	governance *rolesvc.Governance,
) *appcrud.Hooks[*iamentity.Role, int64] {
	return &appcrud.Hooks[*iamentity.Role, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.Role) error {
			if governance != nil {
				return governance.PrepareCreate(ctx, entity)
			}
			tenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			entity.SetTenantID(tenantID)
			entity.SetOwnerID(svc.TenantOwnerID(tenantID))
			if scopeAuthorizer != nil {
				tenantCtx, bindErr := svc.BindTenantContext(ctx, tenantID)
				if bindErr != nil {
					return bindErr
				}
				namespaceScope, err := scopeAuthorizer.ResolveTenantScope(tenantCtx, tenantID)
				if err != nil {
					return err
				}
				entity.NamespaceScopeID = namespaceScope.ID
			} else {
				if entity.NamespaceScopeID <= 0 {
					entity.NamespaceScopeID = svc.ManagedScopeIDFromContext(ctx)
				}
			}
			if entity.NamespaceScopeID <= 0 {
				return errorx.New(errorx.InvalidInput, "namespace scope boundary is required")
			}
			return nil
		},
		BeforeUpdate: func(ctx context.Context, entity *iamentity.Role) error {
			if governance != nil {
				return governance.PrepareUpdate(ctx, entity)
			}
			contextTenantID, err := domaincrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			if entity != nil && entity.GetID() > 0 {
				current, _, err := loadTenantBoundEntity(ctx, repo, entity.GetID())
				if err != nil {
					return err
				}
				entity.SetTenantID(current.GetTenantID())
				entity.SetOwnerID(current.GetOwnerID())
				if entity.NamespaceScopeID <= 0 {
					entity.NamespaceScopeID = current.NamespaceScopeID
				}
			}
			if entity.GetTenantID() != contextTenantID {
				return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
			}
			if entity.GetOwnerID() == "" {
				entity.SetOwnerID(svc.TenantOwnerID(contextTenantID))
			}
			return nil
		},
		BeforeDelete: func(ctx context.Context, id int64) error {
			if governance != nil {
				return governance.ValidateDelete(ctx, id)
			}
			return checkTenantOwnership(ctx, repo, id)
		},
	}
}

// TenantHooksForTenant 在创建 tenant 时自动补齐 root scope。
func TenantHooksForTenant(
	repo svc.IResourceContextRepository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
) *appcrud.Hooks[*iamentity.Tenant, int64] {
	return &appcrud.Hooks[*iamentity.Tenant, int64]{
		BeforeCreate: func(ctx context.Context, entity *iamentity.Tenant) error {
			if entity == nil {
				return nil
			}
			entity.RootScopeID = nil
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
			current, _, err := loadTenantBoundEntity(ctx, repo, entity.GetID())
			if err != nil {
				return err
			}
			entity.RootScopeID = current.RootScopeID
			return nil
		},
	}
}

func newScopeBackedRoleCRUDHooks(
	repo svc.IResourceContextRepository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	governance *rolesvc.Governance,
) *appcrud.Hooks[*iamentity.Role, int64] {
	return TenantHooksForRole(repo, scopeAuthorizer, governance)
}

func newTenantCRUDHooks(
	repo svc.IResourceContextRepository[*iamentity.Tenant, int64],
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
func checkTenantOwnership[T tenantOwner[ID], ID comparable](
	ctx context.Context,
	repo svc.IResourceContextRepository[T, ID],
	id ID,
) error {
	contextTenantID, err := domaincrud.ResolveTenantID(ctx)
	if err != nil {
		return err
	}
	entity, _, err := loadTenantBoundEntity(ctx, repo, id)
	if err != nil {
		return err
	}
	if entity.GetTenantID() != contextTenantID {
		return errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}
	return nil
}
