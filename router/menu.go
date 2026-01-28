package router

import (
	menusvc "gochen-iam/service/menu"
	httpx "gochen/httpx"
	hbasic "gochen/httpx/nethttp"
	"gochen/runtime/errorx"
)

// MenuRoutes 菜单路由注册器。
//
// 约定：
// - 菜单仅用于“导航可见性”，不作为安全边界；安全边界仍由 API 权限校验保证。
// - /menus/me 返回基于当前请求上下文的菜单树（tenant override + 权限过滤）。
type MenuRoutes struct {
	menuService *menusvc.MenuService
	utils       *hbasic.Utils
}

func NewMenuRoutes(menuService *menusvc.MenuService) *MenuRoutes {
	return &MenuRoutes{
		menuService: menuService,
		utils:       &hbasic.Utils{},
	}
}

func (mr *MenuRoutes) RegisterRoutes(group httpx.IRouteGroup) {
	menuGroup := group.Group("/menus")

	// 当前用户可见菜单（必须已登录）
	meGroup := menuGroup.Group("/me")
	meGroup.Use(UserOnlyMiddleware())
	meGroup.GET("", mr.getMyMenuTree)

	// 管理端：菜单定义与租户覆盖（管理员 + 细分权限）
	adminGroup := menuGroup.Group("")
	adminGroup.Use(AdminOnlyMiddleware())

	adminReadGroup := adminGroup.Group("")
	adminReadGroup.Use(PermissionMiddleware("menu:read"))
	adminReadGroup.GET("", mr.listMenuItems)

	adminWriteGroup := adminGroup.Group("")
	adminWriteGroup.Use(PermissionMiddleware("menu:write"))
	adminWriteGroup.POST("", mr.createMenuItem)
	adminWriteGroup.PUT("/:id", mr.updateMenuItem)
	adminWriteGroup.DELETE("/:id", mr.deleteMenuItem)

	adminPublishGroup := adminGroup.Group("")
	adminPublishGroup.Use(PermissionMiddleware("menu:publish"))
	adminPublishGroup.POST("/:id/publish", mr.publishMenuItem)
	adminPublishGroup.POST("/:id/unpublish", mr.unpublishMenuItem)

	// 租户覆盖（显式 tenant_id；用于管理员为不同租户配置差异）
	tenantGroup := adminGroup.Group("/tenants/:tenant_id")
	tenantReadGroup := tenantGroup.Group("")
	tenantReadGroup.Use(PermissionMiddleware("menu:read"))
	tenantReadGroup.GET("/overrides", mr.listTenantOverrides)

	tenantWriteGroup := tenantGroup.Group("")
	tenantWriteGroup.Use(PermissionMiddleware("menu:write"))
	tenantWriteGroup.PUT("/overrides/:menu_code", mr.upsertTenantOverride)
	tenantWriteGroup.DELETE("/overrides/:menu_code", mr.deleteTenantOverride)
}

func (mr *MenuRoutes) GetName() string { return "menu" }

func (mr *MenuRoutes) GetPriority() int {
	// 低于 auth/user 等基础路由即可
	return 210
}

func (mr *MenuRoutes) listMenuItems(ctx httpx.IContext) error {
	items, err := mr.menuService.ListMenuItems(ctx.GetRequest().Context())
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, items)
	return nil
}

func (mr *MenuRoutes) createMenuItem(ctx httpx.IContext) error {
	req := &menusvc.CreateMenuItemRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	item, err := mr.menuService.CreateMenuItem(ctx.GetRequest().Context(), req)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, item)
	return nil
}

func (mr *MenuRoutes) updateMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	req := &menusvc.UpdateMenuItemRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	item, err := mr.menuService.UpdateMenuItem(ctx.GetRequest().Context(), id, req)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, item)
	return nil
}

func (mr *MenuRoutes) deleteMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	if err := mr.menuService.DeleteMenuItem(ctx.GetRequest().Context(), id); err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, map[string]any{"id": id})
	return nil
}

func (mr *MenuRoutes) publishMenuItem(ctx httpx.IContext) error {
	return mr.setMenuPublished(ctx, true)
}

func (mr *MenuRoutes) unpublishMenuItem(ctx httpx.IContext) error {
	return mr.setMenuPublished(ctx, false)
}

func (mr *MenuRoutes) setMenuPublished(ctx httpx.IContext, published bool) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.PublishMenuItem(ctx.GetRequest().Context(), id, published)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, item)
	return nil
}

func (mr *MenuRoutes) listTenantOverrides(ctx httpx.IContext) error {
	tenantID := ctx.GetParam("tenant_id")
	if tenantID == "" {
		return errorx.NewError(errorx.Validation, "tenant_id is required")
	}
	overrides, err := mr.menuService.ListTenantOverrides(ctx.GetRequest().Context(), tenantID)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, overrides)
	return nil
}

func (mr *MenuRoutes) upsertTenantOverride(ctx httpx.IContext) error {
	tenantID := ctx.GetParam("tenant_id")
	if tenantID == "" {
		return errorx.NewError(errorx.Validation, "tenant_id is required")
	}
	menuCode := ctx.GetParam("menu_code")
	if menuCode == "" {
		return errorx.NewError(errorx.Validation, "menu_code is required")
	}
	req := &menusvc.UpsertTenantOverrideRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	o, err := mr.menuService.UpsertTenantOverride(ctx.GetRequest().Context(), tenantID, menuCode, req)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, o)
	return nil
}

func (mr *MenuRoutes) deleteTenantOverride(ctx httpx.IContext) error {
	tenantID := ctx.GetParam("tenant_id")
	if tenantID == "" {
		return errorx.NewError(errorx.Validation, "tenant_id is required")
	}
	menuCode := ctx.GetParam("menu_code")
	if menuCode == "" {
		return errorx.NewError(errorx.Validation, "menu_code is required")
	}
	if err := mr.menuService.DeleteTenantOverride(ctx.GetRequest().Context(), tenantID, menuCode); err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, map[string]any{"tenant_id": tenantID, "menu_code": menuCode})
	return nil
}

func (mr *MenuRoutes) getMyMenuTree(ctx httpx.IContext) error {
	menus, err := mr.menuService.GetMyMenuTree(ctx.GetRequest().Context(), ctx.GetContext())
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, menus)
	return nil
}
