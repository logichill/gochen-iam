package router

import (
	"context"
	"strconv"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	iamtenant "gochen-iam/tenant"
	"gochen-runtime/api/rest"
	runtimehttp "gochen-runtime/http"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	"gochen/errors"
	"gochen/httpx"
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
	groupService *groupsvc.GroupService
}

// NewGroupRoutes 创建组织路由注册器
func NewGroupRoutes(
	groupService *groupsvc.GroupService,
) (*GroupRoutes, error) {
	if groupService == nil || groupService.HTTPApplication() == nil {
		return nil, errors.NewCode(errors.InvalidInput, "group routes require the declared group service and its actual HTTP application")
	}
	application, ok := groupService.HTTPApplication().(interface {
		AuthorizationBinding(string) (auth.EntryBinding, error)
	})
	if !ok {
		return nil, errors.NewCode(errors.InvalidInput, "group HTTP application must expose its actual resource bindings")
	}
	for _, action := range []string{appcrud.ActionRead, appcrud.ActionList, appcrud.ActionCreate, appcrud.ActionUpdate, appcrud.ActionDelete} {
		if _, err := application.AuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	for _, action := range []string{"add_user", "remove_user", "bulk_add_users", "add_role", "remove_role"} {
		if _, err := groupService.AssociationAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	if _, err := groupService.StatisticsAuthorizationBinding(); err != nil {
		return nil, err
	}
	if _, err := groupService.TreeAuthorizationBinding(); err != nil {
		return nil, err
	}
	for _, action := range []string{"roots", "by_level", "users", "roles"} {
		if _, err := groupService.ReadAuthorizationBinding(action); err != nil {
			return nil, err
		}
	}
	return &GroupRoutes{
		groupService: groupService,
	}, nil
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

	app := gr.groupService.HTTPApplication()

	if err := rest.Mount(adminGroup, app,
		rest.WithQuerySchema[*iamentity.Group, int64](groupQuerySchema),
		rest.WithPagination[*iamentity.Group, int64](10, 1000),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build group crud routes").WithContext("route", "iam.group")
		}
		return errors.Wrap(err, errors.Internal, "failed to build group crud routes").WithContext("route", "iam.group")
	}

	// 组织扩展功能
	return gr.setupGroupCustomRoutes(adminGroup)
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
func (gr *GroupRoutes) setupGroupCustomRoutes(groupGroup httpx.IRouteGroup) error {
	// 组织查询操作（放在参数路由之前，避免冲突）
	registry, _, err := runtimehttp.EntryRegistryFrom(groupGroup)
	if err != nil {
		return err
	}
	statistics, err := gr.groupService.StatisticsAuthorizationBinding()
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(groupGroup, "GET", "/statistics", statistics); err != nil {
			return err
		}
	}
	if err := runtimehttp.RegisterRoute(groupGroup, "GET", "/statistics", gr.getGroupStatistics); err != nil {
		return err
	}
	tree, err := gr.groupService.TreeAuthorizationBinding()
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(groupGroup, "GET", "/tree", tree); err != nil {
			return err
		}
	}
	if err := runtimehttp.RegisterRoute(groupGroup, "GET", "/tree", gr.getGroupTree); err != nil {
		return err
	}

	// 按层级查询（使用查询参数而不是路径参数）

	// 组织成员管理（使用ID参数的路由）

	// 组织角色管理
	for _, entry := range []struct {
		path, action string
		handler      httpx.Handler
	}{
		{"/roots", "roots", gr.getRootGroups}, {"/search/by-level", "by_level", gr.getGroupsByLevel}, {"/:id/users", "users", gr.getGroupUsers}, {"/:id/roles", "roles", gr.getGroupRoles},
	} {
		binding, err := gr.groupService.ReadAuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(groupGroup, "GET", entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(groupGroup, "GET", entry.path, entry.handler); err != nil {
			return err
		}
	}
	return gr.registerAssociationRoutes(groupGroup)
}

func (gr *GroupRoutes) registerAssociationRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		method, path, action string
		handler              httpx.Handler
	}{
		{"POST", "/:id/users", "add_user", gr.addUserToGroup},
		{"DELETE", "/:id/users/:user", "remove_user", gr.removeUserFromGroup},
		{"POST", "/:id/users/bulk", "bulk_add_users", gr.bulkAddUsersToGroup},
		{"POST", "/:id/roles", "add_role", gr.addGroupRole},
		{"DELETE", "/:id/roles/:role", "remove_role", gr.removeGroupRole},
	} {
		binding, err := gr.groupService.AssociationAuthorizationBinding(entry.action)
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

// 组织处理器方法
// 注意：基础CRUD操作（GET, POST, PUT, DELETE /groups）已通过自动注册实现
// 以下只包含扩展功能的处理器

// 组织树操作处理器
func (gr *GroupRoutes) getGroupTree(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()

	tree, err := gr.groupService.GroupTreeHTTP(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, tree)
}

// getRootGroups 返回RootGroups。
func (gr *GroupRoutes) getRootGroups(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	out, err := gr.groupService.ExecuteReadHTTP(reqCtx, "roots", groupsvc.GroupReadInput{})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, out.Groups)
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
	out, err := gr.groupService.ExecuteReadHTTP(reqCtx, "by_level", groupsvc.GroupReadInput{Level: level})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"level":  level,
		"groups": out.Groups,
	})
}

// 组织成员管理处理器
func (gr *GroupRoutes) getGroupUsers(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	out, err := gr.groupService.ExecuteReadHTTP(reqCtx, "users", groupsvc.GroupReadInput{ID: groupID})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"users":    out.Users,
	})
}

// addUserToGroup 添加用户到分组。
func (gr *GroupRoutes) addUserToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := httpx.ParseInt64Param(ctx, "id")
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

	if _, err := gr.groupService.ExecuteAssociationHTTP(reqCtx, "add_user", groupsvc.GroupAssociationInput{ID: groupID, RelatedIDs: []int64{req.UserID}}); err != nil {
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
	groupID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	userID, err := httpx.ParseInt64Param(ctx, "user")
	if err != nil {
		return err
	}

	if _, err := gr.groupService.ExecuteAssociationHTTP(reqCtx, "remove_user", groupsvc.GroupAssociationInput{ID: groupID, RelatedIDs: []int64{userID}}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"user_id":  userID,
	})
}

// bulkAddUsersToGroup 处理批量把用户加入分组。
func (gr *GroupRoutes) bulkAddUsersToGroup(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := httpx.ParseInt64Param(ctx, "id")
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

	result, err := gr.groupService.ExecuteAssociationHTTP(reqCtx, "bulk_add_users", groupsvc.GroupAssociationInput{ID: groupID, RelatedIDs: req.UserIDs})
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
	groupID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	out, err := gr.groupService.ExecuteReadHTTP(reqCtx, "roles", groupsvc.GroupReadInput{ID: groupID})
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"group_id": groupID,
		"roles":    out.Roles,
	})
}

// addGroupRole 添加分组角色。
func (gr *GroupRoutes) addGroupRole(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	groupID, err := httpx.ParseInt64Param(ctx, "id")
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

	if _, err := gr.groupService.ExecuteAssociationHTTP(reqCtx, "add_role", groupsvc.GroupAssociationInput{ID: groupID, RelatedIDs: []int64{req.RoleID}}); err != nil {
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
	groupID, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	roleID, err := httpx.ParseInt64Param(ctx, "role")
	if err != nil {
		return err
	}

	if _, err := gr.groupService.ExecuteAssociationHTTP(reqCtx, "remove_role", groupsvc.GroupAssociationInput{ID: groupID, RelatedIDs: []int64{roleID}}); err != nil {
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

	stats, err := gr.groupService.GroupStatisticsHTTP(reqCtx)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, stats)
}

func newGroupCRUDHooks(repo svc.IResourceContextRepository[*iamentity.Group, int64], groupServices ...IGroupService) appcrud.Hooks[*iamentity.Group] {
	return appcrud.Hooks[*iamentity.Group]{
		appcrud.ActionCreate: {
			Before: func(ctx context.Context, group *iamentity.Group) error {
				// 1. 租户隔离：从上下文注入 tenant_id
				tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
		},
		appcrud.ActionUpdate: {
			Before: func(ctx context.Context, group *iamentity.Group) error {
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
		},
		appcrud.ActionDelete: {
			Before: func(ctx context.Context, group *iamentity.Group) error {
				if err := checkTenantOwnership(ctx, repo, group.GetID()); err != nil {
					return err
				}
				if len(groupServices) > 0 && groupServices[0] != nil {
					return groupServices[0].ValidateDelete(ctx, group.GetID())
				}
				return nil
			},
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
