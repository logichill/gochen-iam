package router

import (
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	"gochen/api/restapi"
	appcrud "gochen/app/crud"
	auth "gochen/auth/core"
	"gochen/db/query"
	"gochen/errors"
	"gochen/httpx"
	"gochen/httpx/nethttp"
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
	utils           *nethttp.Utils
	roleRepo        svc.IScopedResourceContextRepository[*iamentity.Role, int64]
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      auth.IAuthorizer
	governance      *rolesvc.Governance
}

// NewRoleRoutes 创建角色路由注册器
func NewRoleRoutes(
	roleService IRoleService,
	roleRepo svc.IScopedResourceContextRepository[*iamentity.Role, int64],
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *auth.Authorizer,
) *RoleRoutes {
	var governance *rolesvc.Governance
	if provider, ok := roleService.(interface{ Governance() *rolesvc.Governance }); ok {
		governance = provider.Governance()
	}
	return &RoleRoutes{
		roleService:     roleService,
		utils:           &nethttp.Utils{},
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
	// 角色基础CRUD - 使用 shared/httpx/api 构建器
	roleGroup := group.Group("/roles")

	// 角色管理属于管理员权限
	adminGroup := roleGroup.Group("")
	adminGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceRole, iammw.ActionManage).Scope(iammw.ScopePlatform, iammw.ScopeTenant),
	))

	appService, err := svc.NewCRUDApplication[*iamentity.Role, int64](rr.roleRepo, rr.roleRepo)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create role crud application").WithContext("route", "iam.role")
		}
		return errors.Wrap(err, errors.Internal, "failed to create role crud application").WithContext("route", "iam.role")
	}

	builder, err := restapi.NewApiBuilder(
		appService,
		restapi.WithQuerySchema[*iamentity.Role, int64](roleQuerySchema),
		restapi.WithAuthorization[*iamentity.Role, int64](rr.authorizer, restapi.CRUDPermissions{
			List:   svc.RolePermissionSet.Code(iammw.ActionRead),
			Get:    svc.RolePermissionSet.Code(iammw.ActionRead),
			Create: svc.RolePermissionSet.Code(iammw.ActionWrite),
			Update: svc.RolePermissionSet.Code(iammw.ActionWrite),
			Delete: svc.RolePermissionSet.Code(iammw.ActionDelete),
		}),
		restapi.WithHooks[*iamentity.Role, int64](func(h *appcrud.Hooks[*iamentity.Role, int64]) {
			*h = *newScopeBackedRoleCRUDHooks(rr.roleRepo, rr.scopeAuthorizer, rr.governance)
		}),
	)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create role api builder").WithContext("route", "iam.role")
		}
		return errors.Wrap(err, errors.Internal, "failed to create role api builder").WithContext("route", "iam.role")
	}
	if err := builder.
		Route(func(cfg *restapi.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = auth.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(roleGroup); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build role crud routes").WithContext("route", "iam.role")
		}
		return errors.Wrap(err, errors.Internal, "failed to build role crud routes").WithContext("route", "iam.role")
	}

	// 角色扩展功能
	rr.setupRoleCustomRoutes(adminGroup)
	return nil
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
func (rr *RoleRoutes) setupRoleCustomRoutes(roleGroup httpx.IRouteGroup) {
	// 角色权限管理
	roleGroup.GET("/:id/permissions", rr.getRolePermissions)
	roleGroup.POST("/:id/permissions", rr.addRolePermission)
	roleGroup.DELETE("/:id/permissions/:permission", rr.removeRolePermission)

	// 角色用户管理
	roleGroup.GET("/:id/users", rr.getRoleUsers)
	roleGroup.POST("/:id/users", rr.assignRoleToUsers)
	roleGroup.DELETE("/:id/users/:user", rr.removeRoleFromUser)

	// 角色操作
	roleGroup.POST("/:id/activate", rr.activateRole)
	roleGroup.POST("/:id/deactivate", rr.deactivateRole)
	roleGroup.POST("/:id/clone", rr.cloneRole)

	// 系统角色
	roleGroup.GET("/system", rr.getSystemRoles)
	roleGroup.POST("/system/init", rr.initSystemRoles)

	// 角色统计
	roleGroup.GET("/statistics", rr.getRoleStatistics)
}

// 角色处理器方法
// 注意：基础CRUD操作（GET, POST, PUT, DELETE /roles）已通过自动注册实现
// 以下只包含扩展功能的处理器

// 角色权限管理处理器
func (rr *RoleRoutes) getRolePermissions(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	role, _, err := loadTenantBoundEntity(reqCtx, rr.roleRepo, roleID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"role_id":     roleID,
		"permissions": role.Permissions,
	})
}

// addRolePermission 添加角色权限。
func (rr *RoleRoutes) addRolePermission(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	roleID, err := rr.utils.ParseID(ctx, "id")
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
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	permission := ctx.Param("permission")
	if permission == "" {
		err := errors.NewCode(errors.Validation, "permission is required")
		return err
	}

	if err := rr.roleService.RemovePermission(reqCtx, roleID, permission); err != nil {
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
	roleID, err := rr.utils.ParseID(ctx, "id")
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
	roleID, err := rr.utils.ParseID(ctx, "id")
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

	result, err := rr.roleService.BatchAssignRole(reqCtx, req)
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
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	userID, err := rr.utils.ParseID(ctx, "user")
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
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.ActivateRole(reqCtx, roleID); err != nil {
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
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.DeactivateRole(reqCtx, roleID); err != nil {
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
	roleID, err := rr.utils.ParseID(ctx, "id")
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
	roles, err := rr.roleService.SystemRoles(reqCtx)
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
	stats, err := rr.roleService.RoleStatistics(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, stats)
}
