package router

import (
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	restapi "gochen/api/restapi"
	appcrud "gochen/app/crud"
	"gochen/authz"
	dataquery "gochen/db/query"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

type userQueryFields struct {
	ID          int64
	Username    string
	Email       string
	Status      string `query:"type=enum,ops=eq"`
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

var userQuerySchema = dataquery.MustInferQuerySchema[userQueryFields](nil)

// UserRoutes 用户路由注册器
type UserRoutes struct {
	userService IUserService
	utils       *hbasic.Utils
	userRepo    domaincrud.IResourceBoundaryRepository[*iamentity.User, int64]
	authorizer  authz.IAuthorizer
}

// NewUserRoutes 创建用户路由注册器
func NewUserRoutes(
	userService IUserService,
	userRepo domaincrud.IResourceBoundaryRepository[*iamentity.User, int64],
	authorizer *authz.Authorizer,
) *UserRoutes {
	return &UserRoutes{
		userService: userService,
		utils:       &hbasic.Utils{},
		userRepo:    userRepo,
		authorizer:  authorizer,
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
	adminGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceUser, iammw.ActionManage).Scope(iammw.ScopePlatform, iammw.ScopeTenant),
	))

	// 直接使用原生 shared 仓储接口（UserRepo 已实现 ICRUDRepository）
	appService, err := appcrud.NewApplication(ur.userRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create user crud application").WithContext("route", "iam.user")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create user crud application").WithContext("route", "iam.user")
	}

	builder, err := restapi.NewApiBuilder(
		appService,
		restapi.WithQuerySchema[*iamentity.User, int64](userQuerySchema),
		restapi.WithAuthorization[*iamentity.User, int64](ur.authorizer, restapi.CRUDPermissions{
			List:   "api:user:read",
			Get:    "api:user:read",
			Create: "api:user:write",
			Update: "api:user:write",
			Delete: "api:user:delete",
		}),
		restapi.WithHooks[*iamentity.User, int64](func(h *appcrud.Hooks[*iamentity.User, int64]) {
			*h = *TenantHooksForUser(ur.userRepo)
		}),
	)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create user api builder").WithContext("route", "iam.user")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create user api builder").WithContext("route", "iam.user")
	}

	if err := builder.
		Route(func(cfg *restapi.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = authz.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(userGroup); err != nil {
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

// Name 获取注册器名称
func (ur *UserRoutes) Name() string {
	return "user"
}

// Priority 获取注册优先级
func (ur *UserRoutes) Priority() int {
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
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.ActivateUser(reqCtx, userID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusActive,
	})
}

// deactivateUser 处理deactivate用户。
func (ur *UserRoutes) deactivateUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.DeactivateUser(reqCtx, userID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusInactive,
	})
}

// lockUser 处理lock用户。
func (ur *UserRoutes) lockUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.LockUser(reqCtx, userID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusLocked,
	})
}

// unlockUser 处理unlock用户。
func (ur *UserRoutes) unlockUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	if err := ur.userService.UnlockUser(reqCtx, userID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"id":     userID,
		"status": iamsvc.UserStatusActive,
	})
}

// 用户角色管理处理器
func (ur *UserRoutes) getUserRoles(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roles, err := ur.userService.UserRoles(reqCtx, userID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"roles": roles,
	})
}

// assignUserRole 分配用户角色。
func (ur *UserRoutes) assignUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id": userID,
		"role_id": req.RoleID,
	})
}

// removeUserRole 移除用户角色。
func (ur *UserRoutes) removeUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id": userID,
		"role_id": roleID,
	})
}

// 用户组织管理处理器
func (ur *UserRoutes) getUserGroups(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	groups, err := ur.userService.UserGroups(reqCtx, userID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"groups": groups,
	})
}

// assignUserToGroup 分配用户到分组。
func (ur *UserRoutes) assignUserToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":  userID,
		"group_id": req.GroupID,
	})
}

// removeUserFromGroupByUser 移除用户从分组按用户。
func (ur *UserRoutes) removeUserFromGroupByUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":  userID,
		"group_id": groupID,
	})
}

// 用户权限处理器
func (ur *UserRoutes) getUserPermissions(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := ur.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	permissions, err := ur.userService.UserPermissions(reqCtx, userID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":     userID,
		"permissions": permissions,
	})
}

// checkUserPermission 处理check用户权限。
func (ur *UserRoutes) checkUserPermission(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":    userID,
		"permission": req.Permission,
		"allowed":    allowed,
	})
}

// 当前用户处理器
func (ur *UserRoutes) getCurrentUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID := iammw.GetUserID(ctx.RequestContext())
	if userID == 0 {
		err := errorx.New(errorx.Unauthorized, "用户未认证")
		return err
	}

	user, err := ur.userService.UserProfile(reqCtx, userID)
	if err != nil {
		return err
	}
	if user != nil {
		user.Password = ""
	}

	return httpx.WriteSuccess(ctx, user)
}

// updateCurrentUser 更新当前用户。
func (ur *UserRoutes) updateCurrentUser(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID := iammw.GetUserID(ctx.RequestContext())
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

	return httpx.WriteSuccess(ctx, user)
}

// changePassword 处理change密码。
func (ur *UserRoutes) changePassword(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID := iammw.GetUserID(ctx.RequestContext())
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id": userID,
		"status":  "password_changed",
	})
}
