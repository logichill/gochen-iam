package router

import (
	"context"
	"strconv"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen/api/rest"
	appcrud "gochen/app/crud"
	auth "gochen/auth"
	"gochen/db/query"
	"gochen/errors"
	"gochen/httpx"
	"gochen/httpx/nethttp"
)

type groupQueryFields struct {
	ID        int64
	Name      string
	ParentID  *int64
	Level     int
	Path      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var groupQuerySchema = query.MustInferQuerySchema[groupQueryFields](nil)

// GroupRoutes 组织路由注册器
type GroupRoutes struct {
	groupService IGroupService
	utils        *nethttp.Utils
	groupRepo    svc.IScopedResourceContextRepository[*iamentity.Group, int64]
	authorizer   auth.IAuthorizer
}

// NewGroupRoutes 创建组织路由注册器
func NewGroupRoutes(
	groupService IGroupService,
	groupRepo svc.IScopedResourceContextRepository[*iamentity.Group, int64],
	authorizer *auth.Authorizer,
) *GroupRoutes {
	return &GroupRoutes{
		groupService: groupService,
		utils:        &nethttp.Utils{},
		groupRepo:    groupRepo,
		authorizer:   authorizer,
	}
}

// RegisterRoutes 注册路由。
func (gr *GroupRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	// 组织基础CRUD - 使用 shared/httpx/api 构建器
	groupGroup := group.Group("/groups")

	adminGroup := groupGroup.Group("")
	adminGroup.Use(iammw.PermissionMiddleware(
		iammw.ApiPermission(iammw.ResourceGroup, iammw.ActionManage).Scope(iammw.ScopePlatform, iammw.ScopeTenant),
	))

	appService, err := svc.NewCRUDApplication[*iamentity.Group, int64](gr.groupRepo, gr.groupRepo)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create group crud application").WithContext("route", "iam.group")
		}
		return errors.Wrap(err, errors.Internal, "failed to create group crud application").WithContext("route", "iam.group")
	}

	builder, err := rest.NewApiBuilder[*iamentity.Group, int64](
		appService,
		rest.WithQuerySchema[*iamentity.Group, int64](groupQuerySchema),
		rest.WithAuthorization[*iamentity.Group, int64](gr.authorizer, rest.CRUDPermissions{
			List:   svc.GroupPermissionSet.Code(iammw.ActionRead),
			Get:    svc.GroupPermissionSet.Code(iammw.ActionRead),
			Create: svc.GroupPermissionSet.Code(iammw.ActionWrite),
			Update: svc.GroupPermissionSet.Code(iammw.ActionWrite),
			Delete: svc.GroupPermissionSet.Code(iammw.ActionDelete),
		}),
		rest.WithHooks[*iamentity.Group, int64](func(h *appcrud.Hooks[*iamentity.Group, int64]) {
			*h = *newGroupCRUDHooks(gr.groupRepo)
		}),
	)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("create group api builder").WithContext("route", "iam.group")
		}
		return errors.Wrap(err, errors.Internal, "failed to create group api builder").WithContext("route", "iam.group")
	}
	if err := builder.
		Route(func(cfg *rest.RouteConfig[int64]) {
			cfg.EnableBatch = false
			cfg.EnablePagination = true
			cfg.DefaultPageSize = 10
			cfg.MaxPageSize = 1000
			if cfg.Authorization != nil {
				cfg.Authorization.Consistency = auth.ConsistencyModeStrong
				cfg.Authorization.HighRisk = true
			}
		}).
		Build(groupGroup); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build group crud routes").WithContext("route", "iam.group")
		}
		return errors.Wrap(err, errors.Internal, "failed to build group crud routes").WithContext("route", "iam.group")
	}

	// 组织扩展功能
	gr.setupGroupCustomRoutes(adminGroup)
	return nil
}

// Name 获取注册器名称
func (gr *GroupRoutes) Name() string {
	return "group"
}

// Priority 获取注册优先级
func (gr *GroupRoutes) Priority() int {
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
	reqCtx := ctx.RequestContext()

	tree, err := gr.groupService.GroupTree(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, tree)
}

// getRootGroups 返回RootGroups。
func (gr *GroupRoutes) getRootGroups(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	tenantID, err := svc.TenantIDFromContext(reqCtx)
	if err != nil {
		return err
	}

	groups, err := gr.groupService.RootGroups(reqCtx, tenantID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, groups)
}

// getGroupsByLevel 返回Groups按等级。
func (gr *GroupRoutes) getGroupsByLevel(ctx httpx.IContext) error {
	levelStr := ctx.Query("level")
	if levelStr == "" {
		err := errors.NewCode(errors.Validation, "level parameter is required")
		return err
	}

	level, err := strconv.Atoi(levelStr)
	if err != nil || level <= 0 {
		err := errors.NewCode(errors.Validation, "level must be a positive integer")
		return err
	}

	reqCtx := ctx.RequestContext()
	groups, err := gr.groupService.GroupsByLevel(reqCtx, level)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"level":  level,
		"groups": groups,
	})
}

// 组织成员管理处理器
func (gr *GroupRoutes) getGroupUsers(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	users, err := gr.groupService.GroupUsers(reqCtx, groupID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"users":    users,
	})
}

// addUserToGroup 添加用户到分组。
func (gr *GroupRoutes) addUserToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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
		err := errors.NewCode(errors.Validation, "user_id must be greater than 0")
		return err
	}

	if err := gr.groupService.AddUserToGroup(reqCtx, groupID, req.UserID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"user_id":  req.UserID,
	})
}

// removeUserFromGroup 移除用户从分组。
func (gr *GroupRoutes) removeUserFromGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"user_id":  userID,
	})
}

// batchAddUsersToGroup 处理批量AddUsers到分组。
func (gr *GroupRoutes) batchAddUsersToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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
		err := errors.NewCode(errors.Validation, "user_ids cannot be empty")
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id":      groupID,
		"success_count": result.SuccessCount,
		"failure_count": result.FailureCount,
		"errors":        errorMessages,
	})
}

// 组织角色管理处理器
func (gr *GroupRoutes) getGroupRoles(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := gr.utils.ParseID(ctx, "id")
	if err != nil {
		return err
	}

	roles, err := gr.groupService.GroupRoles(reqCtx, groupID)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"roles":    roles,
	})
}

// addGroupRole 添加分组角色。
func (gr *GroupRoutes) addGroupRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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
		err := errors.NewCode(errors.Validation, "role_id must be greater than 0")
		return err
	}

	if err := gr.groupService.AddGroupRole(reqCtx, groupID, req.RoleID); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"role_id":  req.RoleID,
	})
}

// removeGroupRole 移除分组角色。
func (gr *GroupRoutes) removeGroupRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
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

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"role_id":  roleID,
	})
}

// 组织统计处理器
func (gr *GroupRoutes) getGroupStatistics(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()

	stats, err := gr.groupService.GroupStatistics(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, stats)
}

func newGroupCRUDHooks(repo svc.IResourceContextRepository[*iamentity.Group, int64]) *appcrud.Hooks[*iamentity.Group, int64] {
	return &appcrud.Hooks[*iamentity.Group, int64]{
		BeforeCreate: func(ctx context.Context, group *iamentity.Group) error {
			// 1. 租户隔离：从上下文注入 tenant_id
			tenantID, err := appcrud.ResolveTenantID(ctx)
			if err != nil {
				return err
			}
			managedScopeID := svc.ManagedScopeIDFromContext(ctx)
			if managedScopeID <= 0 {
				return errors.NewCode(errors.InvalidInput, "managed scope boundary is required")
			}
			group.SetTenantID(tenantID)
			group.SetManagedScopeID(managedScopeID)
			group.SetOwnerID(svc.TenantOwnerID(tenantID))
			// 2. 层级准备
			return prepareGroupHierarchy(ctx, repo, nil, group)
		},
		BeforeUpdate: func(ctx context.Context, group *iamentity.Group) error {
			if group == nil {
				return errors.NewCode(errors.InvalidInput, "group cannot be nil")
			}
			current, _, err := loadTenantBoundEntity(ctx, repo, group.GetID())
			if err != nil {
				return err
			}
			// 更新时始终沿用已存在实体的租户，避免请求体伪造/遗漏 tenant_id。
			group.SetTenantID(current.GetTenantID())
			group.SetManagedScopeID(current.GetManagedScopeID())
			group.SetOwnerID(current.GetOwnerID())
			return prepareGroupHierarchy(ctx, repo, current, group)
		},
		BeforeDelete: func(ctx context.Context, id int64) error {
			return checkTenantOwnership(ctx, repo, id)
		},
	}
}

func prepareGroupHierarchy(
	ctx context.Context,
	repo svc.IResourceContextRepository[*iamentity.Group, int64],
	current *iamentity.Group,
	group *iamentity.Group,
) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ParentID == nil {
		group.SetParent(nil)
		return nil
	}
	if current != nil && *group.ParentID == current.GetID() {
		return errors.NewCode(errors.Validation, "不能将组织设置为自己的父组织")
	}

	parent, _, err := loadTenantBoundEntity(ctx, repo, *group.ParentID)
	if err != nil {
		return errors.Wrap(err, errors.NotFound, "父组织不存在")
	}
	if parent.Level >= svc.MaxGroupLevel {
		return errors.NewCode(errors.Validation, "组织层级不能超过10级")
	}
	if current != nil && current.IsAncestorOf(parent) {
		return errors.NewCode(errors.Validation, "不能将组织移动到其子组织下")
	}

	group.SetParent(parent)
	return nil
}
