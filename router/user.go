package router

import (
	iammw "gochen-iam/middleware"
	userrepo "gochen-iam/repo/user"
	iamsvc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	usersvc "gochen-iam/service/user"
	api "gochen/api/http"
	appcrud "gochen/app/crud"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// UserRoutes 用户路由注册器
type UserRoutes struct {
	userService  *usersvc.UserService
	groupService *groupsvc.GroupService
	roleService  *rolesvc.RoleService
	utils        *hbasic.Utils
	userRepo     *userrepo.UserRepo
}

// NewUserRoutes 创建用户路由注册器
func NewUserRoutes(userService *usersvc.UserService, groupService *groupsvc.GroupService, roleService *rolesvc.RoleService, userRepo *userrepo.UserRepo) *UserRoutes {
	return &UserRoutes{
		userService:  userService,
		groupService: groupService,
		roleService:  roleService,
		utils:        &hbasic.Utils{},
		userRepo:     userRepo,
	}
}

// RegisterRoutes 注册路由。
func (ur *UserRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errorx.New(errorx.InvalidInput, "route group cannot be nil")
	}
	// 用户基础CRUD - 使用 shared/httpx/api 构建器
	userGroup := group.Group("/users")

	// 管理操作（包括基础 CRUD 和对任意用户的管理）仅对管理员开放
	adminGroup := userGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())

	// 直接使用原生 shared 仓储接口（UserRepo 已实现 ICRUDRepository）
	appService, err := appcrud.NewApplication(ur.userRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create user crud application").WithContext("route", "iam.user")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create user crud application").WithContext("route", "iam.user")
	}

	builder, err := api.NewApiBuilder(appService, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create user api builder").WithContext("route", "iam.user")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create user api builder").WithContext("route", "iam.user")
	}

	if err := builder.
		Route(func(cfg *api.RouteConfig[int64]) {
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("build user crud routes").WithContext("route", "iam.user")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to build user crud routes").WithContext("route", "iam.user")
	}

	// 用户扩展功能
	ur.setupAdminUserRoutes(adminGroup)
	ur.setupSelfUserRoutes(userGroup)
	return nil
}

// GetName 获取注册器名称
func (ur *UserRoutes) GetName() string {
	return "user"
}

// GetPriority 获取注册优先级
func (ur *UserRoutes) GetPriority() int {
	return 100 // 用户路由优先级为100
}

// setupAdminUserRoutes 设置管理员可用的用户管理路由
func (ur *UserRoutes) setupAdminUserRoutes(userGroup httpx.IRouteGroup) {
	// 用户状态管理
	userGroup.POST("/:id/activate", ur.activateUser)
	userGroup.POST("/:id/deactivate", ur.deactivateUser)
	userGroup.POST("/:id/lock", ur.lockUser)
	userGroup.POST("/:id/unlock", ur.unlockUser)

	// 用户角色管理
	userGroup.GET("/:id/roles", ur.getUserRoles)
	userGroup.POST("/:id/roles", ur.assignUserRole)
	userGroup.DELETE("/:id/roles/:role", ur.removeUserRole)

	// 用户组织管理
	userGroup.GET("/:id/groups", ur.getUserGroups)
	userGroup.POST("/:id/groups", ur.assignUserToGroup)
	userGroup.DELETE("/:id/groups/:group", ur.removeUserFromGroupByUser)

	// 用户权限查询
	userGroup.GET("/:id/permissions", ur.getUserPermissions)
	userGroup.POST("/:id/check-permission", ur.checkUserPermission)
}

// setupSelfUserRoutes 设置当前用户自助操作路由
func (ur *UserRoutes) setupSelfUserRoutes(userGroup httpx.IRouteGroup) {
	meGroup := userGroup.Group("/me")
	meGroup.Use(iammw.UserOnlyMiddleware())

	meGroup.GET("", ur.getCurrentUser)
	meGroup.PUT("", ur.updateCurrentUser)
	meGroup.POST("/change-password", ur.changePassword)
}

// 用户处理器方法
// 注意：基础CRUD操作（GET, POST, PUT, DELETE /users）已通过自动注册实现
// 以下只包含扩展功能的处理器

// 用户状态管理处理器
func (ur *UserRoutes) activateUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.ActivateUser(reqCtx, userID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusActive,
	})
	return nil
}

func (ur *UserRoutes) deactivateUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.DeactivateUser(reqCtx, userID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusInactive,
	})
	return nil
}

func (ur *UserRoutes) lockUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.LockUser(reqCtx, userID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusLocked,
	})
	return nil
}

func (ur *UserRoutes) unlockUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.UnlockUser(reqCtx, userID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusActive,
	})
	return nil
}

// 用户角色管理处理器
func (ur *UserRoutes) getUserRoles(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roles, err := ur.userService.GetUserRoles(reqCtx, userID)
	if err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"roles": roles,
	})
	return nil
}

func (ur *UserRoutes) assignUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		RoleID int64 `json:"role_id" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if req.RoleID <= 0 {
		err := errorx.New(errorx.Validation, "role_id must be greater than 0")
		return err
	}

	if err := ur.userService.AssignRole(reqCtx, userID, req.RoleID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id": userID,
		"role_id": req.RoleID,
	})
	return nil
}

func (ur *UserRoutes) removeUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roleID, err := ur.utils.ParseID(ctx, "role")
	if err != nil {
		return err
	}

	if err := ur.userService.RemoveRole(reqCtx, userID, roleID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id": userID,
		"role_id": roleID,
	})
	return nil
}

// 用户组织管理处理器
func (ur *UserRoutes) getUserGroups(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	groups, err := ur.userService.GetUserGroups(reqCtx, userID)
	if err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"groups": groups,
	})
	return nil
}

func (ur *UserRoutes) assignUserToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		GroupID int64 `json:"group_id" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if req.GroupID <= 0 {
		err := errorx.New(errorx.Validation, "group_id must be greater than 0")
		return err
	}

	if err := ur.userService.AssignToGroup(reqCtx, userID, req.GroupID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id":  userID,
		"group_id": req.GroupID,
	})
	return nil
}

func (ur *UserRoutes) removeUserFromGroupByUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	groupID, err := ur.utils.ParseID(ctx, "group")
	if err != nil {
		return err
	}

	if err := ur.userService.RemoveFromGroup(reqCtx, userID, groupID); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id":  userID,
		"group_id": groupID,
	})
	return nil
}

// 用户权限处理器
func (ur *UserRoutes) getUserPermissions(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	permissions, err := ur.userService.GetUserPermissions(reqCtx, userID)
	if err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id":     userID,
		"permissions": permissions,
	})
	return nil
}

func (ur *UserRoutes) checkUserPermission(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID, err := ur.utils.ParseID(ctx, "id")
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

	allowed, err := ur.userService.CheckPermission(reqCtx, userID, req.Permission)
	if err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id":    userID,
		"permission": req.Permission,
		"allowed":    allowed,
	})
	return nil
}

// 当前用户处理器
func (ur *UserRoutes) getCurrentUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID := ctx.GetContext().GetUserID()
	if userID == 0 {
		err := errorx.New(errorx.Unauthorized, "用户未认证")
		return err
	}

	user, err := ur.userService.GetUserProfile(reqCtx, userID)
	if err != nil {
		return err
	}
	if user != nil {
		user.Password = ""
	}

	ur.utils.WriteSuccessResponse(ctx, user)
	return nil
}

func (ur *UserRoutes) updateCurrentUser(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID := ctx.GetContext().GetUserID()
	if userID == 0 {
		err := errorx.New(errorx.Unauthorized, "用户未认证")
		return err
	}

	req := &iamsvc.UpdateUserRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}

	user, err := ur.userService.UpdateProfile(reqCtx, userID, req)
	if err != nil {
		return err
	}
	if user != nil {
		user.Password = ""
	}

	ur.utils.WriteSuccessResponse(ctx, user)
	return nil
}

func (ur *UserRoutes) changePassword(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	userID := ctx.GetContext().GetUserID()
	if userID == 0 {
		err := errorx.New(errorx.Unauthorized, "用户未认证")
		return err
	}

	req := &iamsvc.ChangePasswordRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}

	if err := ur.userService.ChangePassword(reqCtx, userID, req); err != nil {
		return err
	}

	ur.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"user_id": userID,
		"status":  "password_changed",
	})
	return nil
}
