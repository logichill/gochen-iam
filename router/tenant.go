package router

import (
	"context"

	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	api "gochen/api/http"
	appcrud "gochen/app/crud"
	httpx "gochen/httpx"
	hbasic "gochen/httpx/nethttp"
	"gochen/runtime/logging"
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
func (tr *TenantRoutes) RegisterRoutes(group httpx.IRouteGroup) {
	tenantGroup := group.Group("/tenants")

	// 租户管理仅对管理员开放
	adminGroup := tenantGroup.Group("")
	adminGroup.Use(AdminOnlyMiddleware())

	appService, err := appcrud.NewApplication(tr.tenantRepo, nil, nil)
	if err != nil {
		// 记录错误并返回：模块层已不再使用 panic 控制流。
		logging.GetLogger().Error(context.Background(), "创建租户 CRUD 应用服务失败",
			logging.Error(err))
		return
	}
	_ = api.NewApiBuilder(appService, nil).
		Route(func(cfg *api.RouteConfig[int64]) {
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 100
		}).
		Build(adminGroup)

	tr.setupTenantCustomRoutes(adminGroup)
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
