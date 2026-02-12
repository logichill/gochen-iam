package router

import (
	iammw "gochen-iam/middleware"
	menusvc "gochen-iam/service/menu"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// MenuRoutes 菜单路由注册器。
//
// 约定：
// - 菜单仅用于“导航可见性”，不作为安全边界；安全边界仍由 API 权限校验保证。
// - /menus/me 返回基于当前请求上下文的菜单树（权限过滤）。
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

func (mr *MenuRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	menuGroup := group.Group("/menus")

	// 当前用户可见菜单（必须已登录）
	meGroup := menuGroup.Group("/me")
	meGroup.Use(iammw.UserOnlyMiddleware())
	meGroup.GET("", mr.getMyMenuTree)

	// 管理端：菜单定义与发布（管理员 + 细分权限）
	adminGroup := menuGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())
	// 说明：当前设计“仅允许 system_admin 管理菜单”。
	// menu:read/menu:write/menu:publish 仍会通过 PermissionMiddleware 注册到 required permissions，用于权限治理与审计。
	// 如需支持“非 system_admin 但具备 menu:* 权限的角色”管理菜单：移除 AdminOnlyMiddleware，仅保留 PermissionMiddleware。

	adminReadGroup := adminGroup.Group("")
	adminReadGroup.Use(iammw.PermissionMiddleware("menu:read"))
	adminReadGroup.GET("", mr.listMenuItems)

	adminWriteGroup := adminGroup.Group("")
	adminWriteGroup.Use(iammw.PermissionMiddleware("menu:write"))
	adminWriteGroup.POST("", mr.createMenuItem)
	adminWriteGroup.PUT("/:id", mr.updateMenuItem)
	adminWriteGroup.DELETE("/:id", mr.deleteMenuItem)
	adminWriteGroup.POST("/:id/restore", mr.restoreMenuItem)
	adminWriteGroup.DELETE("/:id/purge", mr.purgeMenuItem)

	adminPublishGroup := adminGroup.Group("")
	adminPublishGroup.Use(iammw.PermissionMiddleware("menu:publish"))
	adminPublishGroup.POST("/:id/publish", mr.publishMenuItem)
	adminPublishGroup.POST("/:id/unpublish", mr.unpublishMenuItem)

	return nil
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

func (mr *MenuRoutes) restoreMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.RestoreMenuItem(ctx.GetRequest().Context(), id)
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, item)
	return nil
}

func (mr *MenuRoutes) purgeMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	if err := mr.menuService.PurgeMenuItem(ctx.GetRequest().Context(), id); err != nil {
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

func (mr *MenuRoutes) getMyMenuTree(ctx httpx.IContext) error {
	menus, err := mr.menuService.GetMyMenuTree(ctx.GetRequest().Context(), ctx.GetContext())
	if err != nil {
		return err
	}
	mr.utils.WriteSuccessResponse(ctx, menus)
	return nil
}
