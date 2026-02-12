package router

import (
	iammw "gochen-iam/middleware"
	rolerepo "gochen-iam/repo/role"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	usersvc "gochen-iam/service/user"
	api "gochen/api/http"
	appcrud "gochen/app/crud"
	"gochen/errorx"
	"gochen/httpx"
	"gochen/httpx/nethttp"
)

// RoleRoutes 角色路由注册器
type RoleRoutes struct {
	roleService  *rolesvc.RoleService
	userService  *usersvc.UserService
	groupService *groupsvc.GroupService
	utils        *nethttp.Utils
	roleRepo     *rolerepo.RoleRepo
}

// NewRoleRoutes 创建角色路由注册器
func NewRoleRoutes(roleService *rolesvc.RoleService, userService *usersvc.UserService, groupService *groupsvc.GroupService, roleRepo *rolerepo.RoleRepo) *RoleRoutes {
	return &RoleRoutes{
		roleService:  roleService,
		userService:  userService,
		groupService: groupService,
		utils:        &nethttp.Utils{},
		roleRepo:     roleRepo,
	}
}

// RegisterRoutes 注册路由。
func (rr *RoleRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errorx.New(errorx.InvalidInput, "route group cannot be nil")
	}
	// 角色基础CRUD - 使用 shared/httpx/api 构建器
	roleGroup := group.Group("/roles")

	// 角色管理属于管理员权限
	adminGroup := roleGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())

	appService, err := appcrud.NewApplication(rr.roleRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create role crud application").WithContext("route", "iam.role")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create role crud application").WithContext("route", "iam.role")
	}

	builder, err := api.NewApiBuilder(appService, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create role api builder").WithContext("route", "iam.role")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create role api builder").WithContext("route", "iam.role")
	}
	if err := builder.
		Route(func(cfg *api.RouteConfig[int64]) {
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("build role crud routes").WithContext("route", "iam.role")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to build role crud routes").WithContext("route", "iam.role")
	}

	// 角色扩展功能
	rr.setupRoleCustomRoutes(adminGroup)
	return nil
}

// GetName 获取注册器名称
func (rr *RoleRoutes) GetName() string {
	return "role"
}

// GetPriority 获取注册优先级
func (rr *RoleRoutes) GetPriority() int {
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
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	role, err := rr.roleRepo.GetByID(reqCtx, roleID)
	if err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id":     roleID,
		"permissions": role.Permissions,
	})
	return nil
}

func (rr *RoleRoutes) addRolePermission(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
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
		err := errorx.New(errorx.Validation, "permission is required")
		return err
	}

	if err := rr.roleService.AddPermission(reqCtx, roleID, req.Permission); err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id":    roleID,
		"permission": req.Permission,
	})
	return nil
}

func (rr *RoleRoutes) removeRolePermission(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	permission := ctx.GetParam("permission")
	if permission == "" {
		err := errorx.New(errorx.Validation, "permission is required")
		return err
	}

	if err := rr.roleService.RemovePermission(reqCtx, roleID, permission); err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id":    roleID,
		"permission": permission,
	})
	return nil
}

// 角色用户管理处理器
func (rr *RoleRoutes) getRoleUsers(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	users, err := rr.roleService.GetRoleUsers(reqCtx, roleID)
	if err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id": roleID,
		"users":   users,
	})
	return nil
}

func (rr *RoleRoutes) assignRoleToUsers(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	req := &svc.RoleAssignRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	if len(req.UserIDs) == 0 {
		err := errorx.New(errorx.Validation, "user_ids cannot be empty")
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

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id":       roleID,
		"success_count": result.SuccessCount,
		"failure_count": result.FailureCount,
		"errors":        errorMessages,
	})
	return nil
}

func (rr *RoleRoutes) removeRoleFromUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
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

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id": roleID,
		"user_id": userID,
	})
	return nil
}

// 角色操作处理器
func (rr *RoleRoutes) activateRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.ActivateRole(reqCtx, roleID); err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id": roleID,
		"status":  svc.RoleStatusActive,
	})
	return nil
}

func (rr *RoleRoutes) deactivateRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roleID, err := rr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := rr.roleService.DeactivateRole(reqCtx, roleID); err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"role_id": roleID,
		"status":  svc.RoleStatusInactive,
	})
	return nil
}

func (rr *RoleRoutes) cloneRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
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

	rr.utils.WriteSuccessResponse(ctx, clonedRole)
	return nil
}

// 系统角色处理器
func (rr *RoleRoutes) getSystemRoles(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	roles, err := rr.roleService.GetSystemRoles(reqCtx)
	if err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, roles)
	return nil
}

func (rr *RoleRoutes) initSystemRoles(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	if err := rr.roleService.InitializeSystemRoles(reqCtx); err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"initialized": true,
	})
	return nil
}

// 角色统计处理器
func (rr *RoleRoutes) getRoleStatistics(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	stats, err := rr.roleService.GetRoleStatistics(reqCtx)
	if err != nil {
		return err
	}

	rr.utils.WriteSuccessResponse(ctx, stats)
	return nil
}
