package router

import (
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	"gochen-runtime/api/rest"
	runtimehttp "gochen-runtime/http"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/errors"
	"gochen/httpx"
)

type roleQueryFields struct {
	ID        int64
	Code      string
	Name      string
	Status    string `query:"type=enum,ops=eq"`
	IsSystem  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

var roleQuerySchema = query.MustInferQuerySchema[roleQueryFields](nil)

// RoleRoutes 角色路由注册器
type RoleRoutes struct {
	roleService     IRoleService
	roleRepo        appcrud.Repository[*iamentity.Role, int64]
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      *svc.IAMAccess
	governance      *rolesvc.Governance
}

// NewRoleRoutes 创建角色路由注册器
func NewRoleRoutes(
	roleService IRoleService,
	roleRepo appcrud.Repository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAccess,
) *RoleRoutes {
	var governance *rolesvc.Governance
	if provider, ok := roleService.(interface{ Governance() *rolesvc.Governance }); ok {
		governance = provider.Governance()
	}
	return &RoleRoutes{
		roleService:     roleService,
		roleRepo:        roleRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
		governance:      governance,
	}
}

// RegisterRoutes 注册路由。
func (rr *RoleRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	if rr.roleService == nil {
		return errors.NewCode(errors.InvalidInput, "role routes require the declared role service")
	}
	if _, err := rr.roleService.StatisticsAuthorizationBinding(); err != nil {
		return err
	}
	if _, err := rr.roleService.SystemAuthorizationBinding(); err != nil {
		return err
	}
	for _, action := range []string{"activate", "deactivate", "remove_permission"} {
		if _, err := rr.roleService.WriteAuthorizationBinding(action); err != nil {
			return err
		}
	}
	// 角色基础CRUD - 使用 shared/httpx/api 构建器
	roleGroup := group.Group("/roles")

	// 角色管理属于管理员权限
	adminGroup := roleGroup.Group("")
	adminGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceRole, iammw.ActionManage).Scope(iammw.ScopePlatform, iammw.ScopeTenant),
	))

	app := rr.roleService.HTTPApplication()
	if app == nil {
		return errors.NewCode(errors.InvalidInput, "role routes require their constructed multi-resource application")
	}

	if err := rest.Mount(adminGroup, app,
		rest.WithFastDeny[*iamentity.Role, int64](),
		rest.WithQuerySchema[*iamentity.Role, int64](roleQuerySchema),
		rest.WithPagination[*iamentity.Role, int64](10, 1000),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build role crud routes").WithContext("route", "iam.role")
		}
		return errors.Wrap(err, errors.Internal, "failed to build role crud routes").WithContext("route", "iam.role")
	}

	// 角色扩展功能
	return rr.setupRoleCustomRoutes(adminGroup)
}

// Name 获取注册器名称
func (rr *RoleRoutes) Name() string {
	return "role"
}

// Priority 获取注册优先级
func (rr *RoleRoutes) Priority() int {
	return 200 // 角色路由优先级为200
}

// setupRoleCustomRoutes 设置角色自定义路由
func (rr *RoleRoutes) setupRoleCustomRoutes(roleGroup httpx.IRouteGroup) error {
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{
		{"GET", "/:id/permissions", "permissions", rr.getRolePermissions},
		{"POST", "/:id/permissions", "add_permission", rr.addRolePermission},
		{"GET", "/:id/users", "users", rr.getRoleUsers},
		{"POST", "/:id/users", "assign_user", rr.assignRoleToUsers},
		{"DELETE", "/:id/users/:user", "remove_user", rr.removeRoleFromUser},
		{"POST", "/:id/clone", "clone", rr.cloneRole},
		{"POST", "/system/init", "initialize", rr.initSystemRoles},
	} {
		if err := rr.registerCustomExecutionRoute(roleGroup, entry.method, entry.path, entry.action, entry.handler); err != nil {
			return err
		}
	}

	// 角色操作
	if err := rr.registerRoleWriteRoutes(roleGroup); err != nil {
		return err
	}

	// 系统角色
	if err := rr.registerSystemRolesRoute(roleGroup); err != nil {
		return err
	}

	// 角色统计
	return rr.registerRoleStatisticsRoute(roleGroup)
}

func (rr *RoleRoutes) registerRoleWriteRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{{"POST", "/:id/activate", "activate", rr.activateRole}, {"POST", "/:id/deactivate", "deactivate", rr.deactivateRole},
		{"DELETE", "/:id/permissions/:permission", "remove_permission", rr.removeRolePermission}} {
		binding, err := rr.roleService.WriteAuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(group, entry.method, entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, entry.method, entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (rr *RoleRoutes) registerSystemRolesRoute(group httpx.IRouteGroup) error {
	binding, err := rr.roleService.SystemAuthorizationBinding()
	if err != nil {
		return err
	}
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(group, "GET", "/system", binding); err != nil {
			return err
		}
	}
	return runtimehttp.RegisterRoute(group, "GET", "/system", rr.getSystemRoles)
}

func (rr *RoleRoutes) registerRoleStatisticsRoute(roleGroup httpx.IRouteGroup) error {
	binding, err := rr.roleService.StatisticsAuthorizationBinding()
	if err != nil {
		return err
	}
	registry, _, err := runtimehttp.EntryRegistryFrom(roleGroup)
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(roleGroup, "GET", "/statistics", binding); err != nil {
			return err
		}
	}
	return runtimehttp.RegisterRoute(roleGroup, "GET", "/statistics", rr.getRoleStatistics)
}

// 角色处理器方法
// 注意：基础CRUD操作（GET, POST, PUT, DELETE /roles）已通过自动注册实现
// 以下只包含扩展功能的处理器

// 角色权限管理处理器
func (rr *RoleRoutes) getRolePermissions(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	permissions, err := rr.roleService.RolePermissions(reqCtx, roleID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id":     roleID,
		"permissions": permissions,
	})
}

// addRolePermission 添加角色权限。
func (rr *RoleRoutes) addRolePermission(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		Permission string `json:"permission" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if req.Permission == "" {
		err := errors.NewCode(errors.Validation, "permission is required")
		return err
	}

	if err := rr.roleService.AddPermission(reqCtx, roleID, req.Permission); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id":    roleID,
		"permission": req.Permission,
	})
}

// removeRolePermission 移除角色权限。
func (rr *RoleRoutes) removeRolePermission(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	permission := ctx.Param("permission")
	if permission == "" {
		err := errors.NewCode(errors.Validation, "permission is required")
		return err
	}

	if err := rr.roleService.ExecuteWriteHTTP(reqCtx, "remove_permission", rolesvc.RoleWriteInput{ID: roleID, Permission: permission}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id":    roleID,
		"permission": permission,
	})
}

// 角色用户管理处理器
func (rr *RoleRoutes) getRoleUsers(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	users, err := rr.roleService.RoleUsers(reqCtx, roleID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id": roleID,
		"users":   users,
	})
}

// assignRoleToUsers 分配角色到Users。
func (rr *RoleRoutes) assignRoleToUsers(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	req := &svc.RoleAssignRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	if len(req.UserIDs) == 0 {
		err := errors.NewCode(errors.Validation, "user_ids cannot be empty")
		return err
	}
	req.RoleID = roleID

	result, err := rr.roleService.BulkAssignRole(reqCtx, req)
	if err != nil {
		return err
	}

	errorMessages := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		if e != nil {
			errorMessages = append(errorMessages, e.Error())
		}
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id":       roleID,
		"success_count": result.SuccessCount,
		"failure_count": result.FailureCount,
		"errors":        errorMessages,
	})
}

// removeRoleFromUser 移除角色从用户。
func (rr *RoleRoutes) removeRoleFromUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	userID, err := httpx.ParseInt64Param(ctx, "user")
	if err != nil {
		return err
	}

	if err := rr.roleService.RemoveRoleFromUser(reqCtx, roleID, userID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id": roleID,
		"user_id": userID,
	})
}

// 角色操作处理器
func (rr *RoleRoutes) activateRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.ExecuteWriteHTTP(reqCtx, "activate", rolesvc.RoleWriteInput{ID: roleID}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id": roleID,
		"status":  svc.RoleStatusActive,
	})
}

// deactivateRole 处理deactivate角色。
func (rr *RoleRoutes) deactivateRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.ExecuteWriteHTTP(reqCtx, "deactivate", rolesvc.RoleWriteInput{ID: roleID}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id": roleID,
		"status":  svc.RoleStatusInactive,
	})
}

// cloneRole 复制角色。
func (rr *RoleRoutes) cloneRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		Name string `json:"name" binding:"required,min=3,max=50"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}

	clonedRole, err := rr.roleService.CloneRole(reqCtx, roleID, req.Name)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, clonedRole)
}

// 系统角色处理器
func (rr *RoleRoutes) getSystemRoles(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roles, err := rr.roleService.SystemRolesHTTP(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, roles)
}

// initSystemRoles 处理初始化系统Roles。
func (rr *RoleRoutes) initSystemRoles(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	tenantID, err := svc.TenantIDFromContext(reqCtx)
	if err != nil {
		return err
	}
	if err := rr.roleService.InitializeSystemRoles(reqCtx, tenantID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"initialized": true,
	})
}

// 角色统计处理器
func (rr *RoleRoutes) getRoleStatistics(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	stats, err := rr.roleService.RoleStatisticsHTTP(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, stats)
}

func (rr *RoleRoutes) registerCustomExecutionRoute(group httpx.IRouteGroup, method, path, action string, handler httpx.Handler) error {
	binding, err := rr.roleService.CustomAuthorizationBinding(action)
	if err != nil {
		return err
	}
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(group, method, path, binding); err != nil {
			return err
		}
	}
	return runtimehttp.RegisterRoute(group, method, path, handler)
}
