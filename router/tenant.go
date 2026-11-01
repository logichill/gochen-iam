package router

import (
	"context"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-runtime/api/rest"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/errors"
	"gochen/httpx"
)

// TenantRoutes 租户路由注册器
type TenantRoutes struct {
	tenantService    ITenantService
	tenantRepo       appcrud.Repository[*iamentity.Tenant, int64]
	scopeAuthorizer  *svc.ScopeAuthorizer
	authorizer       *svc.IAMAuthorizer
	userRepo         *userrepo.UserRepo
	groupRepo        *grouprepo.GroupRepo
	roleRepo         *rolerepo.RoleRepo
	scopeRepo        *scoperepo.ScopeRepo
	deleteGovernance *tenantDeleteGovernance
}

// NewTenantRoutes 创建租户路由注册器
func NewTenantRoutes(
	tenantService ITenantService,
	tenantRepo appcrud.Repository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAuthorizer,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeRepo *scoperepo.ScopeRepo,
) *TenantRoutes {
	deleteGovernance := newTenantDeleteGovernance(userRepo, groupRepo, roleRepo, scopeRepo)
	return &TenantRoutes{
		tenantService:    tenantService,
		tenantRepo:       tenantRepo,
		scopeAuthorizer:  scopeAuthorizer,
		authorizer:       authorizer,
		userRepo:         userRepo,
		groupRepo:        groupRepo,
		roleRepo:         roleRepo,
		scopeRepo:        scopeRepo,
		deleteGovernance: deleteGovernance,
	}
}

// RegisterRoutes 注册路由
func (tr *TenantRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	tenantGroup := group.Group("/tenants")

	// tenant 资源是 platform-scoped：HTTP 入口先收口 active scope，
	// permission + write guard 再由 builder / service 统一处理。
	adminGroup := tenantGroup.Group("")
	adminGroup.Use(iammw.PlatformScopeMiddleware())

	app, err := appcrud.NewApplication[*iamentity.Tenant, int64](tr.tenantRepo, appcrud.Options[*iamentity.Tenant, int64]{
		Resource:   "tenant",
		Authorizer: tr.authorizer,
		ActionPermissions: map[string]string{
			appcrud.ActionRead:   svc.TenantPermissionSet.Code(iammw.ActionRead),
			appcrud.ActionList:   svc.TenantPermissionSet.Code(iammw.ActionRead),
			appcrud.ActionCreate: svc.TenantPermissionSet.Code(iammw.ActionWrite),
			appcrud.ActionUpdate: svc.TenantPermissionSet.Code(iammw.ActionWrite),
			appcrud.ActionDelete: svc.TenantPermissionSet.Code(iammw.ActionDelete),
		},
		Hooks: TenantHooksForTenant(tr.tenantRepo, tr.scopeAuthorizer, tr.deleteGovernance),
	})
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant crud application").WithContext("route", "iam.tenant")
		}
		return errors.Wrap(err, errors.Internal, "failed to create tenant crud application").WithContext("route", "iam.tenant")
	}

	if err := rest.Mount(adminGroup, app,
		rest.WithPagination[*iamentity.Tenant, int64](10, 100),
		rest.WithResponseWrapper[*iamentity.Tenant, int64](tr.wrapTenantResponse),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build tenant crud routes").WithContext("route", "iam.tenant")
		}
		return errors.Wrap(err, errors.Internal, "failed to build tenant crud routes").WithContext("route", "iam.tenant")
	}

	tr.setupTenantCustomRoutes(adminGroup)
	return nil
}

// Name 获取注册器名称
func (tr *TenantRoutes) Name() string {
	return "tenant"
}

// Priority 获取注册优先级
func (tr *TenantRoutes) Priority() int {
	return 50 // 租户路由优先级，在 auth/user 之后
}

// setupTenantCustomRoutes 设置租户自定义路由
func (tr *TenantRoutes) setupTenantCustomRoutes(group httpx.IRouteGroup) {
	group.POST("/:id/activate", tr.activateTenant)
	group.POST("/:id/deactivate", tr.deactivateTenant)
	group.POST("/:id/repair-root-scope", tr.repairTenantRootScope)
}

func (tr *TenantRoutes) wrapTenantResponse(data any) any {
	switch payload := data.(type) {
	case *iamentity.Tenant:
		return tr.toTenantListItem(payload)
	case []*iamentity.Tenant:
		items := make([]svc.TenantListItem, 0, len(payload))
		for _, tenant := range payload {
			if tenant == nil {
				continue
			}
			items = append(items, tr.toTenantListItem(tenant))
		}
		return map[string]any{
			"items": items,
			"total": len(items),
		}
	case query.PagedResult[*iamentity.Tenant]:
		items := make([]svc.TenantListItem, 0, len(payload.Data))
		for _, tenant := range payload.Data {
			if tenant == nil {
				continue
			}
			items = append(items, tr.toTenantListItem(tenant))
		}
		return map[string]any{
			"items":       items,
			"total":       payload.Total,
			"page":        payload.Page,
			"size":        payload.Size,
			"total_pages": payload.TotalPages,
			"has_next":    payload.HasNext,
			"has_prev":    payload.HasPrev,
		}
	default:
		return data
	}
}

func (tr *TenantRoutes) toTenantListItem(tenant *iamentity.Tenant) svc.TenantListItem {
	item := svc.TenantListItem{
		ID:          tenant.ID,
		Key:         tenant.Key,
		Name:        tenant.Name,
		Description: tenant.Description,
		Status:      tenant.Status,
		RootScopeID: tenant.RootScopeID,
		CreatedAt:   tenant.CreatedAt,
		UpdatedAt:   tenant.UpdatedAt,
		DeletedAt:   tenant.DeletedAt,
	}
	if tr.deleteGovernance != nil {
		state, err := tr.deleteGovernance.State(context.Background(), tenant)
		if err == nil && state != nil {
			item.CanDelete = state.CanDelete
			item.DeleteBlockReason = state.DeleteBlockReason
		}
	}
	if tr.scopeAuthorizer != nil {
		health, err := tr.scopeAuthorizer.TenantRootScopeHealth(context.Background(), tenant)
		if err == nil && health != nil {
			item.RootScopeStatus = health.Status
			item.RootScopeReason = health.Reason
			item.CanRepairRootScope = health.CanRepair
		}
	}
	return item
}

// activateTenant 启用租户
func (tr *TenantRoutes) activateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if err := tr.tenantService.ActivateTenant(reqCtx, id); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusActive,
	})
}

// deactivateTenant 禁用租户
func (tr *TenantRoutes) deactivateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if err := tr.tenantService.DeactivateTenant(reqCtx, id); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusInactive,
	})
}

// repairTenantRootScope 修复租户 root scope。
func (tr *TenantRoutes) repairTenantRootScope(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	scope, err := tr.tenantService.RepairTenantRootScope(reqCtx, id)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":             id,
		"root_scope_id":  scope.ID,
		"root_scope_key": scope.Key,
		"root_scope_status": func() string {
			if scope.IsActive() {
				return iamentity.ScopeStatusActive
			}
			return iamentity.ScopeStatusInactive
		}(),
	})
}
