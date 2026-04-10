package router

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	menusvc "gochen-iam/service/menu"
	restapi "gochen/api/restapi"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// MenuRoutes 菜单路由注册器。
//
// 约定：
// - 菜单仅用于“导航可见性”，不作为安全边界；安全边界仍由 API 权限校验保证。
// - /menus/me 返回基于当前请求上下文的菜单树（按菜单自身 permission 规则过滤）。
type MenuRoutes struct {
	menuService IMenuService
	utils       *hbasic.Utils
}

// NewMenuRoutes 创建菜单路由注册器。
func NewMenuRoutes(menuService IMenuService) *MenuRoutes {
	return &MenuRoutes{
		menuService: menuService,
		utils:       &hbasic.Utils{},
	}
}

// RegisterRoutes 注册菜单相关 HTTP 路由。
func (mr *MenuRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	menuGroup := group.Group("/menus")

	// 1. 注册当前用户菜单树接口，只要求登录即可访问。
	meGroup := menuGroup.Group("/me")
	meGroup.Use(iammw.UserOnlyMiddleware())
	meGroup.GET("", mr.getMyMenuTree)

	// 2. 注册管理端菜单接口：先做管理员门禁，再按读/写/发布能力细分权限。
	adminGroup := menuGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())
	adminGroup.Use(iammw.PlatformScopeMiddleware())
	// 说明：当前设计“仅允许 system_admin 管理菜单”。
	// api:menu:read/api:menu:write/api:menu:publish 仍会通过 PermissionMiddleware 注册到 required permissions，用于权限治理与审计。
	// 如需支持“非 system_admin 但具备 menu:* 权限的角色”管理菜单：移除 AdminOnlyMiddleware，仅保留 PermissionMiddleware。

	adminReadGroup := adminGroup.Group("")
	adminReadGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionRead).Desc("读取菜单").Scope(iammw.ScopePlatform),
	))
	adminReadGroup.GET("", mr.listMenuItems)

	adminWriteGroup := adminGroup.Group("")
	adminWriteGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceMenu, iammw.ActionWrite).Desc("维护菜单").Scope(iammw.ScopePlatform),
	))
	adminWriteGroup.POST("", mr.createMenuItem)
	adminWriteGroup.POST("/sync", mr.syncMenuItems)
	adminWriteGroup.PUT("/:id", mr.updateMenuItem)
	adminWriteGroup.DELETE("/:id", mr.deleteMenuItem)
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

// listMenuItems 返回后台菜单列表。
func (mr *MenuRoutes) listMenuItems(ctx httpx.IContext) error {
	items, err := mr.menuService.ListMenuItems(ctx.RequestContext())
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, items)
}

// createMenuItem 处理创建菜单请求。
func (mr *MenuRoutes) createMenuItem(ctx httpx.IContext) error {
	req := &menusvc.CreateMenuItemRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	item, err := mr.menuService.CreateMenuItem(ctx.RequestContext(), req)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

// updateMenuItem 处理更新菜单请求。
func (mr *MenuRoutes) updateMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	req := &menusvc.UpdateMenuItemRequest{}
	fields, err := restapi.BindJSONBodyFields(ctx, req)
	if err != nil {
		return err
	}
	item, err := mr.menuService.UpdateMenuItem(
		ctx.RequestContext(),
		id,
		req,
		menuUpdatePatches(fields, req)...,
	)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

func menuUpdatePatches(fields restapi.JSONBodyFields, req *menusvc.UpdateMenuItemRequest) []svc.FieldPatch[iamentity.MenuItem] {
	if !fields.Has("parent_id") {
		return nil
	}
	return []svc.FieldPatch[iamentity.MenuItem]{
		svc.ValueFieldPatch(func(item *iamentity.MenuItem, parentID *int64) {
			item.ParentID = parentID
		}, req.ParentID),
	}
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

// deleteMenuItem 处理软删除菜单请求。
func (mr *MenuRoutes) deleteMenuItem(ctx httpx.IContext) error {
	id, err := mr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}
	if err := mr.menuService.DeleteMenuItem(ctx.RequestContext(), id); err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, map[string]any{"id": id})
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
