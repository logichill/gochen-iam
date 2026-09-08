package router

import (
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	"gochen-runtime/api/rest"
	"gochen-runtime/security"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth/action"
	"gochen/auth/scoped"
	"gochen/errors"
	"gochen/httpx"
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

var userQuerySchema = query.MustInferQuerySchema[userQueryFields](nil)

// UserRoutes 用户路由注册器
type UserRoutes struct {
	userService IUserService
	userRepo    iamsvc.IScopedResourceContextRepository[*iamentity.User, int64]
	authorizer  scoped.IAuthorizer
}

// NewUserRoutes 创建用户路由注册器
func NewUserRoutes(
	userService IUserService,
	userRepo iamsvc.IScopedResourceContextRepository[*iamentity.User, int64],
	authorizer scoped.IAuthorizer,
) *UserRoutes {
	return &UserRoutes{
		userService: userService,
		userRepo:    userRepo,
		authorizer:  authorizer,
	}
}

// RegisterRoutes 注册路由。
func (ur *UserRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	// 用户基础CRUD - 使用 shared/httpx/api 构建器
	userGroup := group.Group("/users")

	// 管理操作（包括基础 CRUD 和对任意用户的管理）仅对管理员开放
	adminGroup := userGroup.Group("")
	adminGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceUser, iammw.ActionManage).Scope(iammw.ScopePlatform, iammw.ScopeTenant),
	))

	// 直接使用原生 shared 仓储接口（UserRepo 已实现 ICRUDRepository）
	appService, err := iamsvc.NewCRUDApplication[*iamentity.User, int64](ur.userRepo, ur.userRepo)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create user crud application").WithContext("route", "iam.user")
		}
		return errors.Wrap(err, errors.Internal, "failed to create user crud application").WithContext("route", "iam.user")
	}

	var app appcrud.IApplication[*iamentity.User, int64] = appService
	if ur.authorizer != nil {
		scopedApp, err := security.Scoped(appService, ur.authorizer, security.ScopedConfig{
			EntityType: iamsvc.UserResourceKind,
			Policy: action.OperationPolicy{
				Create: iammw.ApiPermission(iammw.ResourceUser, iammw.ActionWrite).Code,
				Update: iammw.ApiPermission(iammw.ResourceUser, iammw.ActionWrite).Code,
				Delete: iammw.ApiPermission(iammw.ResourceUser, iammw.ActionDelete).Code,
				Read:   iammw.ApiPermission(iammw.ResourceUser, iammw.ActionRead).Code,
				List:   iammw.ApiPermission(iammw.ResourceUser, iammw.ActionRead).Code,
			},
			ScopeResolver: iamsvc.DefaultDataScopeResolver,
		})
		if err != nil {
			return err
		}
		app = scopedApp
	}

	builder, err := rest.NewApiBuilder[*iamentity.User, int64](
		app,
		rest.WithQuerySchema[*iamentity.User, int64](userQuerySchema),
		rest.WithHooks[*iamentity.User, int64](func(h *appcrud.Hooks[*iamentity.User, int64]) {
			*h = *TenantHooksForUser(ur.userRepo)
		}),
	)

	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create user api builder").WithContext("route", "iam.user")
		}
		return errors.Wrap(err, errors.Internal, "failed to create user api builder").WithContext("route", "iam.user")
	}

	if err := builder.
		Route(func(cfg *rest.RouteConfig[int64]) {
			cfg.Routing.EnableBatch = false
			cfg.Query.EnablePagination = true
			cfg.Query.DefaultPageSize = 10
			cfg.Query.MaxPageSize = 1000
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build user crud routes").WithContext("route", "iam.user")
		}
		return errors.Wrap(err, errors.Internal, "failed to build user crud routes").WithContext("route", "iam.user")
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
	userGroup.GET("/:id/role-bindings", ur.getUserRoleBindings)
	userGroup.POST("/:id/role-bindings", ur.assignUserRoleBinding)
	userGroup.DELETE("/:id/role-bindings/:binding", ur.removeUserRoleBinding)

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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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

// getUserRoleBindings 获取用户直接角色绑定。
func (ur *UserRoutes) getUserRoleBindings(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	bindings, err := ur.userService.UserRoleBindings(reqCtx, userID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id": userID,
		"items":   bindings,
		"total":   len(bindings),
	})
}

// assignUserRole 分配用户角色。
func (ur *UserRoutes) assignUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	req := &iamsvc.AssignUserRoleBindingRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	if req.RoleID <= 0 {
		err := errors.NewCode(errors.Validation, "role_id must be greater than 0")
		return err
	}

	if err := ur.userService.AssignRoleBinding(reqCtx, userID, req.RoleID, req.GrantScopeID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":        userID,
		"role_id":        req.RoleID,
		"grant_scope_id": req.GrantScopeID,
	})
}

// assignUserRoleBinding 在指定 grant scope 下分配用户角色绑定。
func (ur *UserRoutes) assignUserRoleBinding(ctx httpx.IContext) error {
	return ur.assignUserRole(ctx)
}

// removeUserRole 移除用户角色。
func (ur *UserRoutes) removeUserRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	roleID, err := httpx.ParseInt64Param(ctx, "role")
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

// removeUserRoleBinding 按 binding id 移除用户角色绑定。
func (ur *UserRoutes) removeUserRoleBinding(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	bindingID, err := httpx.ParseInt64Param(ctx, "binding")
	if err != nil {
		return err
	}

	if err := ur.userService.RemoveRoleBinding(reqCtx, userID, bindingID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"user_id":    userID,
		"binding_id": bindingID,
	})
}

// 用户组织管理处理器
func (ur *UserRoutes) getUserGroups(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
		err := errors.NewCode(errors.Validation, "group_id must be greater than 0")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	groupID, err := httpx.ParseInt64Param(ctx, "group")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
	userID, err := httpx.ParseInt64Param(ctx, "id")
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
		err := errors.NewCode(errors.Unauthorized, "用户未认证")
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
		err := errors.NewCode(errors.Unauthorized, "用户未认证")
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
		err := errors.NewCode(errors.Unauthorized, "用户未认证")
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
