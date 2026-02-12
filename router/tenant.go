package router

import (
	iammw "gochen-iam/middleware"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	api "gochen/api/http"
	appcrud "gochen/app/crud"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// TenantRoutes 租户路由注册器
type TenantRoutes struct {
	tenantService *tenantsvc.TenantService
	utils         *hbasic.Utils
	tenantRepo    *tenantrepo.TenantRepo
}

// NewTenantRoutes 创建租户路由注册器
func NewTenantRoutes(tenantService *tenantsvc.TenantService, tenantRepo *tenantrepo.TenantRepo) *TenantRoutes {
	return &TenantRoutes{
		tenantService: tenantService,
		utils:         &hbasic.Utils{},
		tenantRepo:    tenantRepo,
	}
}

// RegisterRoutes 注册路由
func (tr *TenantRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errorx.New(errorx.InvalidInput, "route group cannot be nil")
	}
	tenantGroup := group.Group("/tenants")

	// 租户管理仅对管理员开放
	adminGroup := tenantGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())

	appService, err := appcrud.NewApplication(tr.tenantRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant crud application").WithContext("route", "iam.tenant")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create tenant crud application").WithContext("route", "iam.tenant")
	}

	builder, err := api.NewApiBuilder(appService, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create tenant api builder").WithContext("route", "iam.tenant")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create tenant api builder").WithContext("route", "iam.tenant")
	}
	if err := builder.
		Route(func(cfg *api.RouteConfig[int64]) {
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 100
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

// GetName 获取注册器名称
func (tr *TenantRoutes) GetName() string {
	return "tenant"
}

// GetPriority 获取注册优先级
func (tr *TenantRoutes) GetPriority() int {
	return 50 // 租户路由优先级，在 auth/user 之后
}

// setupTenantCustomRoutes 设置租户自定义路由
func (tr *TenantRoutes) setupTenantCustomRoutes(group httpx.IRouteGroup) {
	group.POST("/:id/activate", tr.activateTenant)
	group.POST("/:id/deactivate", tr.deactivateTenant)
}

// activateTenant 启用租户
func (tr *TenantRoutes) activateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	id, err := tr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := tr.tenantService.ActivateTenant(reqCtx, id); err != nil {
		return err
	}

	tr.utils.WriteSuccessResponse(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusActive,
	})
	return nil
}

// deactivateTenant 禁用租户
func (tr *TenantRoutes) deactivateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	id, err := tr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := tr.tenantService.DeactivateTenant(reqCtx, id); err != nil {
		return err
	}

	tr.utils.WriteSuccessResponse(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusInactive,
	})
	return nil
}
