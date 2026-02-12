package router

import (
	"strconv"

	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	usersvc "gochen-iam/service/user"
	api "gochen/api/http"
	appcrud "gochen/app/crud"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// GroupRoutes 组织路由注册器
type GroupRoutes struct {
	groupService *groupsvc.GroupService
	userService  *usersvc.UserService
	roleService  *rolesvc.RoleService
	utils        *hbasic.Utils
	groupRepo    *grouprepo.GroupRepo
}

// NewGroupRoutes 创建组织路由注册器
func NewGroupRoutes(groupService *groupsvc.GroupService, userService *usersvc.UserService, roleService *rolesvc.RoleService, groupRepo *grouprepo.GroupRepo) *GroupRoutes {
	return &GroupRoutes{
		groupService: groupService,
		userService:  userService,
		roleService:  roleService,
		utils:        &hbasic.Utils{},
		groupRepo:    groupRepo,
	}
}

// RegisterRoutes 注册路由。
func (gr *GroupRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errorx.New(errorx.InvalidInput, "route group cannot be nil")
	}
	// 组织基础CRUD - 使用 shared/httpx/api 构建器
	groupGroup := group.Group("/groups")

	adminGroup := groupGroup.Group("")
	adminGroup.Use(iammw.AdminOnlyMiddleware())

	appService, err := appcrud.NewApplication(gr.groupRepo, nil, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create group crud application").WithContext("route", "iam.group")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create group crud application").WithContext("route", "iam.group")
	}

	builder, err := api.NewApiBuilder(appService, nil)
	if err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("create group api builder").WithContext("route", "iam.group")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to create group api builder").WithContext("route", "iam.group")
	}
	if err := builder.
		Route(func(cfg *api.RouteConfig[int64]) {
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
		}).
		Build(adminGroup); err != nil {
		if appErr, ok := err.(*errorx.AppError); ok && appErr != nil {
			return appErr.Wrap("build group crud routes").WithContext("route", "iam.group")
		}
		return errorx.Wrap(err, errorx.Internal, "failed to build group crud routes").WithContext("route", "iam.group")
	}

	// 组织扩展功能
	gr.setupGroupCustomRoutes(adminGroup)
	return nil
}

// GetName 获取注册器名称
func (gr *GroupRoutes) GetName() string {
	return "group"
}

// GetPriority 获取注册优先级
func (gr *GroupRoutes) GetPriority() int {
	return 300 // 组织路由优先级为300
}

// setupGroupCustomRoutes 设置组织自定义路由
func (gr *GroupRoutes) setupGroupCustomRoutes(groupGroup httpx.IRouteGroup) {
	// 组织查询操作（放在参数路由之前，避免冲突）
	groupGroup.GET("/tree", gr.getGroupTree)
	groupGroup.GET("/roots", gr.getRootGroups)
	groupGroup.GET("/statistics", gr.getGroupStatistics)

	// 按层级查询（使用查询参数而不是路径参数）
	groupGroup.GET("/search/by-level", gr.getGroupsByLevel)

	// 组织成员管理（使用ID参数的路由）
	groupGroup.GET("/:id/users", gr.getGroupUsers)
	groupGroup.POST("/:id/users", gr.addUserToGroup)
	groupGroup.DELETE("/:id/users/:user", gr.removeUserFromGroup)
	groupGroup.POST("/:id/users/batch", gr.batchAddUsersToGroup)

	// 组织角色管理
	groupGroup.GET("/:id/roles", gr.getGroupRoles)
	groupGroup.POST("/:id/roles", gr.addGroupRole)
	groupGroup.DELETE("/:id/roles/:role", gr.removeGroupRole)
}

// 组织处理器方法
// 注意：基础CRUD操作（GET, POST, PUT, DELETE /groups）已通过自动注册实现
// 以下只包含扩展功能的处理器

// 组织树操作处理器
func (gr *GroupRoutes) getGroupTree(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()

	tree, err := gr.groupService.GetGroupTree(reqCtx)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, tree)
	return nil
}

func (gr *GroupRoutes) getRootGroups(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()

	groups, err := gr.groupService.GetRootGroups(reqCtx)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, groups)
	return nil
}

func (gr *GroupRoutes) getGroupsByLevel(ctx httpx.IContext) error {
	levelStr := ctx.GetQuery("level")
	if levelStr == "" {
		err := errorx.New(errorx.Validation, "level parameter is required")
		return err
	}

	level, err := strconv.Atoi(levelStr)
	if err != nil || level <= 0 {
		err := errorx.New(errorx.Validation, "level must be a positive integer")
		return err
	}

	reqCtx := ctx.GetRequest().Context()
	groups, err := gr.groupService.GetGroupsByLevel(reqCtx, level)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"level":  level,
		"groups": groups,
	})
	return nil
}

// 组织成员管理处理器
func (gr *GroupRoutes) getGroupUsers(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	users, err := gr.groupService.GetGroupUsers(reqCtx, groupID)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"users":    users,
	})
	return nil
}

func (gr *GroupRoutes) addUserToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		UserID int64 `json:"user_id" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if req.UserID <= 0 {
		err := errorx.New(errorx.Validation, "user_id must be greater than 0")
		return err
	}

	if err := gr.groupService.AddUserToGroup(reqCtx, groupID, req.UserID); err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"user_id":  req.UserID,
	})
	return nil
}

func (gr *GroupRoutes) removeUserFromGroup(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	userID, err := gr.utils.ParseID(ctx, "user")
	if err != nil {
		return err
	}

	if err := gr.groupService.RemoveUserFromGroup(reqCtx, groupID, userID); err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"user_id":  userID,
	})
	return nil
}

func (gr *GroupRoutes) batchAddUsersToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	var req struct {
		UserIDs []int64 `json:"user_ids" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if len(req.UserIDs) == 0 {
		err := errorx.New(errorx.Validation, "user_ids cannot be empty")
		return err
	}

	result, err := gr.groupService.BatchAddUsersToGroup(reqCtx, groupID, req.UserIDs)
	if err != nil {
		return err
	}

	errorMessages := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		if e != nil {
			errorMessages = append(errorMessages, e.Error())
		}
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id":      groupID,
		"success_count": result.SuccessCount,
		"failure_count": result.FailureCount,
		"errors":        errorMessages,
	})
	return nil
}

// 组织角色管理处理器
func (gr *GroupRoutes) getGroupRoles(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roles, err := gr.groupService.GetGroupRoles(reqCtx, groupID)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"roles":    roles,
	})
	return nil
}

func (gr *GroupRoutes) addGroupRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
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

	if err := gr.groupService.AddGroupRole(reqCtx, groupID, req.RoleID); err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"role_id":  req.RoleID,
	})
	return nil
}

func (gr *GroupRoutes) removeGroupRole(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roleID, err := gr.utils.ParseID(ctx, "role")
	if err != nil {
		return err
	}

	if err := gr.groupService.RemoveGroupRole(reqCtx, groupID, roleID); err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"group_id": groupID,
		"role_id":  roleID,
	})
	return nil
}

// 组织统计处理器
func (gr *GroupRoutes) getGroupStatistics(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()

	stats, err := gr.groupService.GetGroupStatistics(reqCtx)
	if err != nil {
		return err
	}

	gr.utils.WriteSuccessResponse(ctx, stats)
	return nil
}
