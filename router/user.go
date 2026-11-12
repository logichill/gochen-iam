package router

import (
	"strconv"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	usersvc "gochen-iam/service/user"
	"gochen-runtime/api/rest"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
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
	userService *usersvc.UserService
}

// NewUserRoutes 创建用户路由注册器
func NewUserRoutes(userService *usersvc.UserService) (*UserRoutes, error) {
	if userService == nil {
		return nil, errors.NewCode(errors.InvalidInput, "user routes require the declared user service")
	}
	for _, action := range []string{"roles", "groups"} {
		if _, err := userService.AssociationReadAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	for _, action := range []string{"activate", "deactivate", "lock", "unlock"} {
		if _, err := userService.StatusAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	for _, action := range []string{"assign_group", "remove_group"} {
		if _, err := userService.GroupWriteAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	if _, err := userService.RoleAssignmentAuthorizationBinding(); err != nil {
		return nil, err
	}
	if _, err := userService.RoleRemovalAuthorizationBinding(); err != nil {
		return nil, err
	}
	if _, err := userService.RoleBindingRemovalAuthorizationBinding(); err != nil {
		return nil, err
	}
	if _, err := userService.RoleBindingReadAuthorizationBinding(); err != nil {
		return nil, err
	}
	if _, err := userService.ListAuthorizationBinding(); err != nil {
		return nil, err
	}
	for _, action := range []string{appcrud.ActionRead, appcrud.ActionCreate, appcrud.ActionUpdate, appcrud.ActionDelete} {
		if _, err := userService.ExistingAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	for _, action := range []string{"profile", "update_profile", "change_password"} {
		if _, err := userService.SelfAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	return &UserRoutes{
		userService: userService,
	}, nil
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
	if err := ur.registerCRUDRoutes(adminGroup); err != nil {
		return err
	}
	if err := ur.setupAdminUserRoutes(adminGroup); err != nil {
		return err
	}
	return ur.setupSelfUserRoutes(userGroup)
}

func (ur *UserRoutes) registerCRUDRoutes(adminGroup httpx.IRouteGroup) error {
	if err := rest.Mount[*iamentity.User, int64](adminGroup, &userHTTPApplication{service: ur.userService},
		rest.WithQuerySchema[*iamentity.User, int64](userQuerySchema),
		rest.WithPagination[*iamentity.User, int64](10, 1000),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build user crud routes").WithContext("route", "iam.user")
		}
		return errors.Wrap(err, errors.Internal, "failed to build user crud routes").WithContext("route", "iam.user")
	}

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
func (ur *UserRoutes) setupAdminUserRoutes(userGroup httpx.IRouteGroup) error {
	if err := ur.registerAssociationReadRoutes(userGroup); err != nil {
		return err
	}
	if err := ur.registerStatusRoutes(userGroup); err != nil {
		return err
	}
	if err := ur.registerGroupWriteRoutes(userGroup); err != nil {
		return err
	}
	if err := ur.registerRoleAssignmentRoutes(userGroup); err != nil {
		return err
	}
	// 用户角色管理
	if err := ur.registerRoleRemovalRoutes(userGroup); err != nil {
		return err
	}
	if err := ur.registerRoleBindingReadRoutes(userGroup); err != nil {
		return err
	}

	// 用户权限查询
	binding, err := ur.userService.PermissionAuthorizationBinding()
	if err != nil {
		return err
	}
	registry, _, err := runtimehttp.EntryRegistryFrom(userGroup)
	if err != nil {
		return err
	}
	for _, route := range []struct {
		method, path string
		handler      httpx.Handler
	}{
		{"GET", "/:id/permissions", ur.getUserPermissions}, {"POST", "/:id/check-permission", ur.checkUserPermission},
	} {
		if registry != nil {
			if err := runtimehttp.BindEntry(userGroup, route.method, route.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(userGroup, route.method, route.path, route.handler); err != nil {
			return err
		}
	}
	return nil
}

func (ur *UserRoutes) registerRoleAssignmentRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	binding, err := ur.userService.RoleAssignmentAuthorizationBinding()
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		path    string
		handler httpx.Handler
	}{{"/:id/roles", ur.assignUserRole}, {"/:id/role-bindings", ur.assignUserRoleBinding}} {
		if registry != nil {
			if err := runtimehttp.BindEntry(group, "POST", entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, "POST", entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (ur *UserRoutes) registerRoleRemovalRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		path    string
		handler httpx.Handler
		binding func() (auth.EntryBinding, error)
	}{{"/:id/roles/:role", ur.removeUserRole, ur.userService.RoleRemovalAuthorizationBinding},
		{"/:id/role-bindings/:binding", ur.removeUserRoleBinding, ur.userService.RoleBindingRemovalAuthorizationBinding}} {
		binding, err := entry.binding()
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(group, "DELETE", entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, "DELETE", entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (ur *UserRoutes) registerRoleBindingReadRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	binding, err := ur.userService.RoleBindingReadAuthorizationBinding()
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(group, "GET", "/:id/role-bindings", binding); err != nil {
			return err
		}
	}
	return runtimehttp.RegisterRoute(group, "GET", "/:id/role-bindings", ur.getUserRoleBindings)
}

func (ur *UserRoutes) registerGroupWriteRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{
		{"POST", "/:id/groups", "assign_group", ur.assignUserToGroup},
		{"DELETE", "/:id/groups/:group", "remove_group", ur.removeUserFromGroupByUser},
	} {
		binding, err := ur.userService.GroupWriteAuthorizationBinding(entry.action)
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

func (ur *UserRoutes) registerStatusRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		action  string
		handler httpx.Handler
	}{{"activate", ur.activateUser}, {"deactivate", ur.deactivateUser}, {"lock", ur.lockUser}, {"unlock", ur.unlockUser}} {
		binding, err := ur.userService.StatusAuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		path := "/:id/" + entry.action
		if registry != nil {
			if err := runtimehttp.BindEntry(group, "POST", path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, "POST", path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (ur *UserRoutes) registerAssociationReadRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		path, action string
		handler      httpx.Handler
	}{{"/:id/roles", "roles", ur.getUserRoles}, {"/:id/groups", "groups", ur.getUserGroups}} {
		binding, err := ur.userService.AssociationReadAuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(group, "GET", entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, "GET", entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

// setupSelfUserRoutes 设置当前用户自助操作路由
func (ur *UserRoutes) setupSelfUserRoutes(userGroup httpx.IRouteGroup) error {
	meGroup := userGroup.Group("/me")
	meGroup.Use(func(ctx httpx.IContext, next func() error) error {
		if _, err := selfUserID(ctx); err != nil {
			return err
		}
		return next()
	})
	registry, _, err := runtimehttp.EntryRegistryFrom(meGroup)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{{"GET", "", "profile", ur.getCurrentUser}, {"PUT", "", "update_profile", ur.updateCurrentUser}, {"POST", "/change-password", "change_password", ur.changePassword}} {
		binding, err := ur.userService.SelfAuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(meGroup, entry.method, entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(meGroup, entry.method, entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func selfUserID(ctx httpx.IContext) (int64, error) {
	principal, err := hostauthz.RequirePrincipal(ctx.RequestContext())
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(principal.SubjectID, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	return id, nil
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

	if err := ur.userService.ExecuteStatusHTTP(reqCtx, "activate", userID); err != nil {
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

	if err := ur.userService.ExecuteStatusHTTP(reqCtx, "deactivate", userID); err != nil {
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

	if err := ur.userService.ExecuteStatusHTTP(reqCtx, "lock", userID); err != nil {
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

	if err := ur.userService.ExecuteStatusHTTP(reqCtx, "unlock", userID); err != nil {
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

	result, err := ur.userService.ExecuteAssociationReadHTTP(reqCtx, "roles", usersvc.UserAssociationReadInput{ID: userID})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"roles": result.Roles,
	})
}

// getUserRoleBindings 获取用户直接角色绑定。
func (ur *UserRoutes) getUserRoleBindings(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	userID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	bindings, err := ur.userService.ExecuteRoleBindingReadHTTP(reqCtx, userID)
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

	if err := ur.userService.ExecuteRoleAssignmentHTTP(reqCtx, usersvc.UserRoleAssignmentInput{UserID: userID, RoleID: req.RoleID, GrantScopeID: req.GrantScopeID}); err != nil {
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

	if err := ur.userService.ExecuteRoleRemovalHTTP(reqCtx, usersvc.UserRoleRemovalInput{UserID: userID, RoleID: roleID}); err != nil {
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

	if err := ur.userService.ExecuteRoleBindingRemovalHTTP(reqCtx, usersvc.UserRoleBindingInput{UserID: userID, BindingID: bindingID}); err != nil {
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

	result, err := ur.userService.ExecuteAssociationReadHTTP(reqCtx, "groups", usersvc.UserAssociationReadInput{ID: userID})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"groups": result.Groups,
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

	if err := ur.userService.ExecuteGroupWriteHTTP(reqCtx, "assign_group", usersvc.UserGroupWriteInput{UserID: userID, GroupID: req.GroupID}); err != nil {
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

	if err := ur.userService.ExecuteGroupWriteHTTP(reqCtx, "remove_group", usersvc.UserGroupWriteInput{UserID: userID, GroupID: groupID}); err != nil {
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
	userID, err := selfUserID(ctx)
	if err != nil {
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
	userID, err := selfUserID(ctx)
	if err != nil {
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
	userID, err := selfUserID(ctx)
	if err != nil {
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
