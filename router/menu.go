package router

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menusvc "gochen-iam/service/menu"
	restapi "gochen/api/restapi"
	"gochen/auth"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// MenuRoutes 菜单路由注册器。
//
// 约定：
// - 菜单仅用于“导航可见性”，不作为安全边界；安全边界仍由 API 权限校验保证。
// - /menus/me 返回基于当前请求上下文的菜单树（按菜单自身 permission 规则过滤）。
type MenuRoutes struct {
	menuService *menusvc.MenuService
	menuRepo    domaincrud.IRepository[*iamentity.MenuItem, int64]
	authorizer  auth.IAuthorizer
	utils       *hbasic.Utils
}

// NewMenuRoutes 创建菜单路由注册器。
func NewMenuRoutes(
	menuService *menusvc.MenuService,
	menuRepo domaincrud.IRepository[*iamentity.MenuItem, int64],
	authorizer *auth.Authorizer,
) *MenuRoutes {
	return &MenuRoutes{
		menuService: menuService,
		menuRepo:    menuRepo,
		authorizer:  authorizer,
		utils:       &hbasic.Utils{},
	}
}

// RegisterRoutes 注册菜单相关 HTTP 路由。
func (mr *MenuRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	menuGroup := group.Group("/menus")

	// 1. 注册当前用户菜单树接口，只要求登录即可访问。
	meGroup := menuGroup.Group("/me")
	meGroup.Use(iammw.UserOnlyMiddleware())
	meGroup.GET("", mr.getMyMenuTree)

	// 2. 注册管理端菜单接口：标准 CRUD 走统一 builder，自定义能力保留独立端点。
	adminGroup := menuGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())
	adminGroup.Use(iammw.PlatformScopeMiddleware())

	menuCRUD, err := menusvc.NewCRUDApplication(mr.menuRepo, mr.menuService)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create menu crud application").WithContext("route", "iam.menu")
		}
		return errors.Wrap(err, errors.Internal, "failed to create menu crud application").WithContext("route", "iam.menu")
	}

	builderOptions := []restapi.Option[*iamentity.MenuItem, int64]{}
	if mr.authorizer != nil {
		builderOptions = append(builderOptions, restapi.WithAuthorization[*iamentity.MenuItem, int64](mr.authorizer, restapi.CRUDPermissions{
			List:   iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionRead).Code,
			Get:    iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionRead).Code,
			Create: iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionWrite).Code,
			Update: iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionWrite).Code,
			Delete: iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionWrite).Code,
		}))
	}
	builder, err := restapi.NewApiBuilder(menuCRUD, builderOptions...)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create menu api builder").WithContext("route", "iam.menu")
		}
		return errors.Wrap(err, errors.Internal, "failed to create menu api builder").WithContext("route", "iam.menu")
	}
	if err := builder.
		Route(func(cfg *restapi.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = false
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = auth.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build menu crud routes").WithContext("route", "iam.menu")
		}
		return errors.Wrap(err, errors.Internal, "failed to build menu crud routes").WithContext("route", "iam.menu")
	}

	adminWriteGroup := adminGroup.Group("")
	adminWriteGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionWrite).Desc("维护菜单").Scope(iammw.ScopePlatform),
	))
	adminWriteGroup.POST("/sync", mr.syncMenuItems)
	adminWriteGroup.POST("/:id/restore", mr.restoreMenuItem)
	adminWriteGroup.DELETE("/:id/purge", mr.purgeMenuItem)

	adminPublishGroup := adminGroup.Group("")
	adminPublishGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionPublish).Desc("发布菜单").Scope(iammw.ScopePlatform),
	))
	adminPublishGroup.POST("/:id/publish", mr.publishMenuItem)
	adminPublishGroup.POST("/:id/unpublish", mr.unpublishMenuItem)

	return nil
}

// Name 返回路由注册器名称。
func (mr *MenuRoutes) Name() string { return "menu" }

// Priority 返回菜单路由的注册优先级。
func (mr *MenuRoutes) Priority() int {
	// 低于 auth/user 等基础路由即可
	return 210
}

// syncMenuItems 处理批量同步菜单请求。
func (mr *MenuRoutes) syncMenuItems(ctx httpx.IContext) error {
	req := &menusvc.SyncMenuItemsRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	result, err := mr.menuService.SyncMenuItems(ctx.RequestContext(), req)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, result)
}

// restoreMenuItem 处理恢复菜单请求。
func (mr *MenuRoutes) restoreMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.RestoreMenuItem(ctx.RequestContext(), id)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

// purgeMenuItem 处理硬删除菜单请求。
func (mr *MenuRoutes) purgeMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	if err := mr.menuService.PurgeMenuItem(ctx.RequestContext(), id); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{"id": id})
}

// publishMenuItem 处理发布菜单请求。
func (mr *MenuRoutes) publishMenuItem(ctx httpx.IContext) error {
	return mr.setMenuPublished(ctx, true)
}

// unpublishMenuItem 处理取消发布菜单请求。
func (mr *MenuRoutes) unpublishMenuItem(ctx httpx.IContext) error {
	return mr.setMenuPublished(ctx, false)
}

// setMenuPublished 统一处理菜单发布状态切换。
func (mr *MenuRoutes) setMenuPublished(ctx httpx.IContext, published bool) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.PublishMenuItem(ctx.RequestContext(), id, published)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

// getMyMenuTree 返回当前用户可见的菜单树。
func (mr *MenuRoutes) getMyMenuTree(ctx httpx.IContext) error {
	menus, err := mr.menuService.MyMenuTree(ctx.RequestContext(), ctx.RequestContext())
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, menus)
}
