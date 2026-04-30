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
	"gochen/api/restapi"
	appcrud "gochen/app/crud"
	auth "gochen/auth/core"
	"gochen/db/query"
	"gochen/errors"
	"gochen/httpx"
	"gochen/httpx/nethttp"
)

// TenantRoutes 租户路由注册器
type TenantRoutes struct {
	tenantService    ITenantService
	utils            *nethttp.Utils
	tenantRepo       svc.IResourceContextRepository[*iamentity.Tenant, int64]
	scopeAuthorizer  *svc.ScopeAuthorizer
	userRepo         *userrepo.UserRepo
	groupRepo        *grouprepo.GroupRepo
	roleRepo         *rolerepo.RoleRepo
	scopeRepo        *scoperepo.ScopeRepo
	deleteGovernance *tenantDeleteGovernance
	authorizer       auth.IAuthorizer
}

// NewTenantRoutes 创建租户路由注册器
func NewTenantRoutes(
	tenantService ITenantService,
	tenantRepo svc.IResourceContextRepository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeRepo *scoperepo.ScopeRepo,
	authorizer *auth.Authorizer,
) *TenantRoutes {
	deleteGovernance := newTenantDeleteGovernance(userRepo, groupRepo, roleRepo, scopeRepo)
	return &TenantRoutes{
		tenantService:    tenantService,
		utils:            &nethttp.Utils{},
		tenantRepo:       tenantRepo,
		scopeAuthorizer:  scopeAuthorizer,
		userRepo:         userRepo,
		groupRepo:        groupRepo,
		roleRepo:         roleRepo,
		scopeRepo:        scopeRepo,
		deleteGovernance: deleteGovernance,
		authorizer:       authorizer,
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

	appService, err := appcrud.NewApplication(tr.tenantRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant crud application").WithContext("route", "iam.tenant")
		}
		return errors.Wrap(err, errors.Internal, "failed to create tenant crud application").WithContext("route", "iam.tenant")
	}

	// 这里故意不传 QuerySchema，直接演示 CRUD builder 的全默认 auto-infer 流程：
	// - QuerySchema 为空；
	// - Allowed* 也为空；
	// - builder 会直接基于 Tenant struct 自动推导查询 schema。
	builder, err := restapi.NewApiBuilder(
		appService,
		restapi.WithAuthorization[*iamentity.Tenant, int64](tr.authorizer, restapi.CRUDPermissions{
			List:   svc.TenantPermissionSet.Code(iammw.ActionRead),
			Get:    svc.TenantPermissionSet.Code(iammw.ActionRead),
			Create: svc.TenantPermissionSet.Code(iammw.ActionWrite),
			Update: svc.TenantPermissionSet.Code(iammw.ActionWrite),
			Delete: svc.TenantPermissionSet.Code(iammw.ActionDelete),
		}),
		func(builder *restapi.ApiBuilder[*iamentity.Tenant, int64]) {
			builder.Route(func(cfg *restapi.RouteConfig[int64]) {
				cfg.ResponseWrapper = tr.wrapTenantResponse
			})
		},
		restapi.WithHooks[*iamentity.Tenant, int64](func(h *appcrud.Hooks[*iamentity.Tenant, int64]) {
			*h = *TenantHooksForTenant(tr.tenantRepo, tr.scopeAuthorizer, tr.deleteGovernance)
		}),
	)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant api builder").WithContext("route", "iam.tenant")
		}
		return errors.Wrap(err, errors.Internal, "failed to create tenant api builder").WithContext("route", "iam.tenant")
	}
	if err := builder.
		Route(func(cfg *restapi.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 100
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = auth.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(adminGroup); err != nil {
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
	case *query.PagedResult[*iamentity.Tenant]:
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
	id, err := tr.utils.ParseID(ctx, "id")
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
	id, err := tr.utils.ParseID(ctx, "id")
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
	id, err := tr.utils.ParseID(ctx, "id")
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
