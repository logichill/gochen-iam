package router

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menusvc "gochen-iam/service/menu"
	"gochen-runtime/api/rest"
	runtimehttp "gochen-runtime/http"
	"gochen/errors"
	"gochen/httpx"
)

// MenuRoutes 菜单路由注册器。
//
// 约定：
// - 菜单仅用于“导航可见性”，不作为安全边界；安全边界仍由 API 权限校验保证。
// - /menus/me 返回基于当前请求上下文的菜单树（按菜单自身 permission 规则过滤）。
type MenuRoutes struct {
	menuService *menusvc.MenuService
}

// NewMenuRoutes 创建菜单路由注册器。
func NewMenuRoutes(menuService *menusvc.MenuService) (*MenuRoutes, error) {
	if menuService == nil || menuService.HTTPApplication() == nil {
		return nil, errors.NewCode(errors.InvalidInput, "menu routes require the declared menu service")
	}
	if _, err := menuService.AuthorizationBinding("sync"); err != nil {
		return nil, err
	}
	return &MenuRoutes{menuService: menuService}, nil
}

// RegisterRoutes 注册菜单相关 HTTP 路由。
func (mr *MenuRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	menuGroup := group.Group("/menus")

	menuGroup.Use(iammw.UserOnlyMiddleware())
	if err := rest.Mount(menuGroup, mr.menuService.HTTPApplication(),
		rest.WithPaginationEnabled[*iamentity.MenuItem, int64](false),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build menu crud routes").WithContext("route", "iam.menu")
		}
		return errors.Wrap(err, errors.Internal, "failed to build menu crud routes").WithContext("route", "iam.menu")
	}

	registry, _, err := runtimehttp.EntryRegistryFrom(menuGroup)
	if err != nil {
		return err
	}
	for _, route := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{
		{"GET", "/me", "my", mr.getMyMenuTree}, {"POST", "/sync", "sync", mr.syncMenuItems}, {"POST", "/:id/restore", "restore", mr.restoreMenuItem}, {"DELETE", "/:id/purge", "purge", mr.purgeMenuItem}, {"POST", "/:id/publish", "publish", mr.publishMenuItem}, {"POST", "/:id/unpublish", "publish", mr.unpublishMenuItem},
	} {
		binding, err := mr.menuService.AuthorizationBinding(route.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(menuGroup, route.method, route.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(menuGroup, route.method, route.path, route.handler); err != nil {
			return err
		}
	}

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
	result, err := mr.menuService.SyncMenuItemsHTTP(ctx.RequestContext(), req)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, result)
}

// restoreMenuItem 处理恢复菜单请求。
func (mr *MenuRoutes) restoreMenuItem(ctx httpx.IContext) error {
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.MenuActionHTTP(ctx.RequestContext(), "restore", id, false)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

// purgeMenuItem 处理硬删除菜单请求。
func (mr *MenuRoutes) purgeMenuItem(ctx httpx.IContext) error {
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	if _, err := mr.menuService.MenuActionHTTP(ctx.RequestContext(), "purge", id, false); err != nil {
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
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}
	item, err := mr.menuService.MenuActionHTTP(ctx.RequestContext(), "publish", id, published)
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, item)
}

// getMyMenuTree 返回当前用户可见的菜单树。
func (mr *MenuRoutes) getMyMenuTree(ctx httpx.IContext) error {
	menus, err := mr.menuService.MyMenuTreeHTTP(ctx.RequestContext())
	if err != nil {
		return err
	}
	return httpx.WriteSuccess(ctx, menus)
}
