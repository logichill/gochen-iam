package router

import (
	"context"
	"fmt"
	"strings"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	appcrud "gochen/app/crud"
	"gochen/db/orm"
	"gochen/domain"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
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
				return errors.NewCode(errors.InvalidInput, "managed scope boundary is required")
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
				return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
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
				return errors.NewCode(errors.InvalidInput, "namespace scope boundary is required")
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
				return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
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
	deleteGovernance *tenantDeleteGovernance,
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
		BeforeDelete: func(ctx context.Context, id int64) error {
			if deleteGovernance == nil {
				return nil
			}
			tenant, err := repo.Get(ctx, id)
			if err != nil {
				return err
			}
			return deleteGovernance.PrepareDelete(ctx, tenant)
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
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeRepo *scoperepo.ScopeRepo,
) *appcrud.Hooks[*iamentity.Tenant, int64] {
	return TenantHooksForTenant(repo, scopeAuthorizer, newTenantDeleteGovernance(userRepo, groupRepo, roleRepo, scopeRepo))
}

type tenantDeleteGovernance struct {
	countUsers        func(ctx context.Context, tenantID string) (int64, error)
	countGroups       func(ctx context.Context, tenantID string) (int64, error)
	countRoles        func(ctx context.Context, tenantID string) (int64, error)
	countScopeChild   func(ctx context.Context, scopeID int64) (int64, error)
	getScope          func(ctx context.Context, scopeID int64) (*iamentity.Scope, error)
	deleteScope       func(ctx context.Context, scope *iamentity.Scope) error
	rebuildScopeGraph func(ctx context.Context) error
}

func newTenantDeleteGovernance(
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeRepo *scoperepo.ScopeRepo,
) *tenantDeleteGovernance {
	if userRepo == nil && groupRepo == nil && roleRepo == nil && scopeRepo == nil {
		return nil
	}
	governance := &tenantDeleteGovernance{}
	if userRepo != nil {
		governance.countUsers = func(ctx context.Context, tenantID string) (int64, error) {
			return countUsersForTenantDelete(ctx, userRepo, tenantID)
		}
	}
	if groupRepo != nil {
		governance.countGroups = func(ctx context.Context, tenantID string) (int64, error) {
			return countGroupsForTenantDelete(ctx, groupRepo, tenantID)
		}
	}
	if roleRepo != nil {
		governance.countRoles = func(ctx context.Context, tenantID string) (int64, error) {
			return countRolesForTenantDelete(ctx, roleRepo, tenantID)
		}
	}
	if scopeRepo != nil {
		governance.countScopeChild = scopeRepo.CountChildren
		governance.getScope = scopeRepo.Get
		governance.deleteScope = func(ctx context.Context, scope *iamentity.Scope) error {
			guard, err := svc.NewPlatformEntityConstraint(ctx, svc.ScopeResourceKind, scope)
			if err != nil {
				return err
			}
			if err := scopeRepo.DeleteWithConstraint(ctx, scope.ID, guard); err != nil {
				return errors.Wrap(err, errors.Database, "删除租户 root scope 失败")
			}
			return nil
		}
		governance.rebuildScopeGraph = scopeRepo.RebuildVisibilityMap
	}
	return governance
}

func (g *tenantDeleteGovernance) PrepareDelete(ctx context.Context, tenant *iamentity.Tenant) error {
	if g == nil || tenant == nil {
		return nil
	}
	state, err := g.State(ctx, tenant)
	if err != nil {
		return err
	}
	if !state.CanDelete {
		return errors.NewCode(errors.Validation, state.DeleteBlockReason)
	}
	if tenant.RootScopeID == nil || *tenant.RootScopeID <= 0 {
		return nil
	}
	if g.getScope == nil || g.deleteScope == nil {
		return errors.NewCode(errors.InvalidInput, "scope repository is required for tenant delete")
	}
	rootScope, err := g.getScope(ctx, *tenant.RootScopeID)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil
		}
		return err
	}
	if err := g.deleteScope(ctx, rootScope); err != nil {
		return err
	}
	if g.rebuildScopeGraph != nil {
		return g.rebuildScopeGraph(ctx)
	}
	return nil
}

func (g *tenantDeleteGovernance) State(ctx context.Context, tenant *iamentity.Tenant) (*svc.TenantGovernanceState, error) {
	if tenant == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
	}

	state := &svc.TenantGovernanceState{
		CanDelete: false,
	}
	if strings.TrimSpace(tenant.Status) != svc.TenantStatusInactive {
		state.DeleteBlockReason = "请先停用租户再删除"
		return state, nil
	}

	tenantID := strings.TrimSpace(tenant.Key)
	if tenantID == "" {
		state.DeleteBlockReason = "租户编码不能为空"
		return state, nil
	}

	if count, err := g.countTenantUsers(ctx, tenantID); err != nil {
		return nil, err
	} else if count > 0 {
		state.DeleteBlockReason = fmt.Sprintf("租户下仍有 %d 个用户，不能删除。", count)
		return state, nil
	}
	if count, err := g.countTenantGroups(ctx, tenantID); err != nil {
		return nil, err
	} else if count > 0 {
		state.DeleteBlockReason = fmt.Sprintf("租户下仍有 %d 个组织，不能删除。", count)
		return state, nil
	}
	if count, err := g.countTenantRoles(ctx, tenantID); err != nil {
		return nil, err
	} else if count > 0 {
		state.DeleteBlockReason = fmt.Sprintf("租户下仍有 %d 个角色，不能删除。", count)
		return state, nil
	}

	if tenant.RootScopeID == nil || *tenant.RootScopeID <= 0 {
		state.CanDelete = true
		return state, nil
	}
	if g.countScopeChild == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope governance is required for tenant delete")
	}
	childCount, err := g.countScopeChild(ctx, *tenant.RootScopeID)
	if err != nil {
		return nil, err
	}
	if childCount > 0 {
		state.DeleteBlockReason = fmt.Sprintf("租户 root scope 下仍有 %d 个子授权域，不能删除。", childCount)
		return state, nil
	}

	state.CanDelete = true
	return state, nil
}

func (g *tenantDeleteGovernance) countTenantUsers(ctx context.Context, tenantID string) (int64, error) {
	if g == nil || g.countUsers == nil {
		return 0, nil
	}
	return g.countUsers(ctx, tenantID)
}

func (g *tenantDeleteGovernance) countTenantGroups(ctx context.Context, tenantID string) (int64, error) {
	if g == nil || g.countGroups == nil {
		return 0, nil
	}
	return g.countGroups(ctx, tenantID)
}

func (g *tenantDeleteGovernance) countTenantRoles(ctx context.Context, tenantID string) (int64, error) {
	if g == nil || g.countRoles == nil {
		return 0, nil
	}
	return g.countRoles(ctx, tenantID)
}

func countUsersForTenantDelete(ctx context.Context, repo *userrepo.UserRepo, tenantID string) (int64, error) {
	engine := repo.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	return countActiveRows[iamentity.User](
		ctx,
		engine,
		"users",
		"(tenant_id = ? OR home_tenant_id = ?) AND deleted_at IS NULL",
		tenantID,
		tenantID,
	)
}

func countGroupsForTenantDelete(ctx context.Context, repo *grouprepo.GroupRepo, tenantID string) (int64, error) {
	engine := repo.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	return countActiveRows[iamentity.Group](
		ctx,
		engine,
		"groups",
		"tenant_id = ? AND deleted_at IS NULL",
		tenantID,
	)
}

func countRolesForTenantDelete(ctx context.Context, repo *rolerepo.RoleRepo, tenantID string) (int64, error) {
	engine := repo.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	return countActiveRows[iamentity.Role](
		ctx,
		engine,
		"roles",
		"tenant_id = ? AND deleted_at IS NULL",
		tenantID,
	)
}

func countActiveRows[T any](ctx context.Context, engine orm.IOrm, table, where string, args ...any) (int64, error) {
	if engine == nil {
		return 0, errors.NewCode(errors.InvalidInput, "orm engine is required")
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[T](),
		Table:        table,
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化治理统计模型失败")
	}
	count, err := model.Count(ctx, orm.WithWhere(where, args...))
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计租户资源占用失败")
	}
	return count, nil
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
		return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
	}
	return nil
}
