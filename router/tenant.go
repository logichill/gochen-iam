package router

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	restapi "gochen/api/restapi"
	appcrud "gochen/app/crud"
	"gochen/authz"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// TenantRoutes 租户路由注册器
type TenantRoutes struct {
	tenantService   ITenantService
	utils           *hbasic.Utils
	tenantRepo      svc.IResourceContextRepository[*iamentity.Tenant, int64]
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      authz.IAuthorizer
}

// NewTenantRoutes 创建租户路由注册器
func NewTenantRoutes(
	tenantService ITenantService,
	tenantRepo svc.IResourceContextRepository[*iamentity.Tenant, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *authz.Authorizer,
) *TenantRoutes {
	return &TenantRoutes{
		tenantService:   tenantService,
		utils:           &hbasic.Utils{},
		tenantRepo:      tenantRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
	}
}

// RegisterRoutes 注册路由
func (tr *TenantRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errorx.New(errorx.InvalidInput, "route group cannot be nil")
	}
	tenantGroup := group.Group("/tenants")

	// tenant 资源是 platform-scoped：HTTP 入口先收口 active scope，
	// permission + write guard 再由 builder / service 统一处理。
	adminGroup := tenantGroup.Group("")
	adminGroup.Use(iammw.PlatformScopeMiddleware())

	appService, err := appcrud.NewApplication(tr.tenantRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant crud application").WithContext("route", "iam.tenant")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create tenant crud application").WithContext("route", "iam.tenant")
	}

	// 这里故意不传 QuerySchema，直接演示 CRUD builder 的全默认 auto-infer 流程：
	// - QuerySchema 为空；
	// - Allowed* 也为空；
	// - builder 会直接基于 Tenant struct 自动推导查询 schema。
	builder, err := restapi.NewApiBuilder(
		appService,
		restapi.WithAuthorization[*iamentity.Tenant, int64](tr.authorizer, restapi.CRUDPermissions{
			List:   "api:tenant:read",
			Get:    "api:tenant:read",
			Create: "api:tenant:write",
			Update: "api:tenant:write",
			Delete: "api:tenant:delete",
		}),
		restapi.WithHooks[*iamentity.Tenant, int64](func(h *appcrud.Hooks[*iamentity.Tenant, int64]) {
			*h = *newTenantCRUDHooks(tr.tenantRepo, tr.scopeAuthorizer)
		}),
	)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant api builder").WithContext("route", "iam.tenant")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create tenant api builder").WithContext("route", "iam.tenant")
	}
	if err := builder.
		Route(func(cfg *restapi.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 100
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = authz.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("build tenant crud routes").WithContext("route", "iam.tenant")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to build tenant crud routes").WithContext("route", "iam.tenant")
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
