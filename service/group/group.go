package group

import (
	"context"
	stdErrors "errors"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	appcrud "gochen/app/crud"
	auth "gochen/auth"
	"gochen/db/query"
	"gochen/errors"
	"gochen/logging"
)

var errBatchAddUsersRollback = stdErrors.New("rollback batch add users to group")

// GroupService 组织服务
type GroupService struct {
	groupRepo       *grouprepo.GroupRepo
	userRepo        *userrepo.UserRepo
	roleRepo        *rolerepo.RoleRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      auth.IAuthorizer
	logger          logging.ILogger
}

// NewGroupService 创建组织服务实例
func NewGroupService(
	groupRepo *grouprepo.GroupRepo,
	userRepo *userrepo.UserRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *auth.Authorizer,
	logger logging.ILogger,
) *GroupService {
	return &GroupService{
		groupRepo:       groupRepo,
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
		logger:          logging.ComponentLogger("iam.service.group", logger),
	}
}

// CreateGroup 创建组织
func (s *GroupService) CreateGroup(ctx context.Context, req *svc.CreateGroupRequest) (*iamentity.Group, error) {
	// 1. 验证请求数据
	if err := s.validateCreateGroupRequest(req); err != nil {
		return nil, err
	}
	tenantID, err := svc.NormalizeTenantID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	managedScopeID := svc.ManagedScopeIDFromContext(tenantCtx)
	if managedScopeID == 0 && s.scopeAuthorizer != nil {
		scope, scopeErr := s.scopeAuthorizer.ResolveTenantScope(tenantCtx, tenantID)
		if scopeErr != nil {
			return nil, scopeErr
		}
		managedScopeID = scope.ID
		tenantCtx, err = svc.BindManagedScopeContext(tenantCtx, managedScopeID)
		if err != nil {
			return nil, err
		}
	}
	if managedScopeID == 0 {
		return nil, errors.NewCode(errors.InvalidInput, "managed scope is required")
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), &iamentity.Group{TenantID: tenantID})
	if err != nil {
		return nil, err
	}

	// 2. 检查父组织是否存在（如果指定了父组织）
	var parentGroup *iamentity.Group
	if req.ParentID != nil {
		parent, err := s.groupRepo.Get(tenantCtx, *req.ParentID)
		if err != nil {
			return nil, errors.Wrap(err, errors.NotFound, "父组织不存在")
		}
		if _, err := svc.PreflightSameTenant(tenantCtx, s.scopeAuthorizer, "", tenantID, parent.TenantID); err != nil {
			return nil, err
		}
		parentGroup = parent

		// 检查层级限制
		if parentGroup.Level >= svc.MaxGroupLevel {
			return nil, errors.NewCode(errors.Validation, "组织层级不能超过10级")
		}
	}

	// 3. 检查组织名称是否重复（同一层级下，租户内）
	if err := s.checkGroupNameDuplicate(ctx, tenantID, req.Name, req.ParentID); err != nil {
		return nil, err
	}

	// 4. 创建组织实体
	group := &iamentity.Group{
		TenantID:       tenantID,
		ManagedScopeID: managedScopeID,
		OwnerID:        svc.TenantOwnerID(tenantID),
		Name:           req.Name,
		Description:    req.Description,
		ParentID:       req.ParentID,
	}
	group.SetUpdatedAt(time.Now())

	// 5. 设置层级和路径
	if parentGroup != nil {
		group.SetParent(parentGroup)
	} else {
		group.Level = 1
	}

	// 6. 保存组织
	if err := s.groupRepo.CreateWithConstraint(tenantCtx, group, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "保存组织失败")
	}

	return group, nil
}

// UpdateGroup 更新组织。
func (s *GroupService) UpdateGroup(
	ctx context.Context,
	groupID int64,
	req *svc.UpdateGroupRequest,
	patches ...svc.FieldPatch[iamentity.Group],
) (*iamentity.Group, error) {
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "update group request is required")
	}

	// 1. 获取组织
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return nil, err
	}

	// 2. 先在候选对象上应用 request + patches，集中做冲突校验。
	candidate := *group
	if req.Name != "" {
		candidate.Name = req.Name
	}
	if req.Description != "" {
		candidate.Description = req.Description
	}
	if err := svc.ApplyFieldPatches(&candidate, patches...); err != nil {
		return nil, err
	}

	parentChanged := !sameParentID((*group).ParentID, candidate.ParentID)
	if parentChanged || candidate.Name != (*group).Name {
		if err := s.checkGroupNameDuplicate(ctx, group.TenantID, candidate.Name, candidate.ParentID); err != nil {
			return nil, err
		}
	}

	if parentChanged && candidate.ParentID != nil {
		if *candidate.ParentID == (*group).GetID() {
			return nil, errors.NewCode(errors.Validation, "不能将组织设置为自己的父组织")
		}
		parent, err := s.groupRepo.Get(tenantCtx, *candidate.ParentID)
		if err != nil {
			return nil, errors.Wrap(err, errors.NotFound, "父组织不存在")
		}
		if _, err := svc.PreflightSameTenant(tenantCtx, s.scopeAuthorizer, "", group.TenantID, parent.TenantID); err != nil {
			return nil, err
		}
		if parent.Level >= svc.MaxGroupLevel {
			return nil, errors.NewCode(errors.Validation, "组织层级不能超过10级")
		}
		if (*group).IsAncestorOf(parent) {
			return nil, errors.NewCode(errors.Validation, "不能将组织移动到其子组织下")
		}
		(*group).SetParent(parent)
	} else if parentChanged && candidate.ParentID == nil {
		(*group).SetParent(nil)
	}
	(*group).Name = candidate.Name
	(*group).Description = candidate.Description
	if err := (*group).Validate(); err != nil {
		return nil, err
	}

	if !parentChanged {
		(*group).SetUpdatedAt(time.Now())
	}
	targets := make([]any, 0, 1)
	targets = append(targets, group)
	if parentChanged {
		descendants, err := s.groupRepo.FindDescendants(tenantCtx, groupID)
		if err != nil {
			return nil, err
		}
		targets = appendGroupTargets(targets, descendants)
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), targets...)
	if err != nil {
		return nil, err
	}

	// 3. 保存更新
	if err := s.groupRepo.UpdateWithConstraint(tenantCtx, group, guard); err != nil {
		return nil, err
	}

	return group, nil
}

func sameParentID(current, next *int64) bool {
	if current == nil || next == nil {
		return current == nil && next == nil
	}
	return *current == *next
}

func appendGroupTargets(targets []any, groups []*iamentity.Group) []any {
	for _, group := range groups {
		if group == nil {
			continue
		}
		targets = append(targets, group)
	}
	return targets
}

// DeleteGroup 删除组织
func (s *GroupService) DeleteGroup(ctx context.Context, tenantID string, groupID int64) error {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(tenantCtx, groupID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionDelete), group)
	if err != nil {
		return err
	}

	// 1. 检查是否有子组织
	children, err := s.groupRepo.FindChildren(tenantCtx, groupID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return errors.NewCode(errors.Validation, "不能删除有子组织的组织，请先处理子组织")
	}

	// 2. 检查是否有用户
	users, err := s.userRepo.FindByGroupID(tenantCtx, groupID)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errors.NewCode(errors.Validation, "不能删除有用户的组织，请先移除用户")
	}

	// 3. 删除组织
	return s.groupRepo.DeleteWithConstraint(tenantCtx, groupID, guard)
}

// GroupTree 获取组织树
func (s *GroupService) GroupTree(ctx context.Context) ([]*svc.GroupTreeNode, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	groups, err := s.groupRepo.GroupTree(tenantCtx)
	if err != nil {
		return nil, err
	}

	var nodes []*svc.GroupTreeNode
	for _, group := range groups {
		nodes = append(nodes, s.buildGroupTreeNode(group))
	}
	return nodes, nil
}

// RootGroups 获取根组织
func (s *GroupService) RootGroups(ctx context.Context, tenantID string) ([]*iamentity.Group, error) {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.groupRepo.FindRootGroups(tenantCtx)
}

// GroupsByLevel 根据层级获取组织
func (s *GroupService) GroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.groupRepo.FindByLevel(tenantCtx, level)
}

// GroupUsers 获取组织用户列表
func (s *GroupService) GroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return nil, err
	}
	if err := svc.RequireAuthorization(ctx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), group); err != nil {
		return nil, err
	}
	return s.userRepo.FindByGroupID(tenantCtx, groupID)
}

// AddUserToGroup 添加用户到组织
func (s *GroupService) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return err
	}
	user, err := s.userRepo.Get(tenantCtx, userID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), group, user)
	if err != nil {
		return err
	}
	return s.groupRepo.AddUserToGroupWithConstraint(tenantCtx, groupID, userID, guard)
}

// RemoveUserFromGroup 从组织移除用户
func (s *GroupService) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return err
	}
	user, err := s.userRepo.Get(tenantCtx, userID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), group, user)
	if err != nil {
		return err
	}
	return s.groupRepo.RemoveUserFromGroupWithConstraint(tenantCtx, groupID, userID, guard)
}

// BatchAddUsersToGroup 批量添加用户到组织（事务包裹）
func (s *GroupService) BatchAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error) {
	response := &svc.BatchOperationResponse{}
	err := appcrud.WithTx(ctx, s.groupRepo, func(txCtx context.Context) error {
		for _, userID := range userIDs {
			if err := s.AddUserToGroup(txCtx, groupID, userID); err != nil {
				response.FailureCount++
				response.Errors = append(response.Errors, err)
			} else {
				response.SuccessCount++
			}
		}
		if response.FailureCount > 0 {
			response.SuccessCount = 0
			return errBatchAddUsersRollback
		}
		return nil
	})
	if err != nil && !stdErrors.Is(err, errBatchAddUsersRollback) {
		return nil, err
	}

	// 如果有任何失败，整个事务回滚，SuccessCount 置零以反映真实状态
	if response.FailureCount > 0 {
		return response, nil
	}
	return response, nil
}

// GroupRoles 获取组织默认角色
func (s *GroupService) GroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return nil, err
	}
	if err := svc.RequireAuthorization(ctx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), group); err != nil {
		return nil, err
	}
	return s.roleRepo.FindByGroupID(tenantCtx, groupID)
}

// AddGroupRole 为组织添加默认角色
func (s *GroupService) AddGroupRole(ctx context.Context, groupID, roleID int64) error {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return err
	}
	role, err := s.roleRepo.Get(tenantCtx, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), group, role)
	if err != nil {
		return err
	}
	return s.groupRepo.AddDefaultRoleWithConstraint(tenantCtx, groupID, roleID, guard)
}

// RemoveGroupRole 移除组织默认角色
func (s *GroupService) RemoveGroupRole(ctx context.Context, groupID, roleID int64) error {
	group, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.groupRepo, groupID)
	if err != nil {
		return err
	}
	role, err := s.roleRepo.Get(tenantCtx, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.GroupPermissionSet.Code(iammw.ActionWrite), group, role)
	if err != nil {
		return err
	}
	return s.groupRepo.RemoveDefaultRoleWithConstraint(tenantCtx, groupID, roleID, guard)
}

// GroupStatistics 获取组织统计信息
func (s *GroupService) GroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.GroupPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	totalGroups, err := s.groupRepo.QueryCount(tenantCtx, query.QueryOptions{})
	if err != nil {
		return nil, err
	}

	totalRoles, err := s.roleRepo.QueryCount(tenantCtx, query.QueryOptions{})
	if err != nil {
		return nil, err
	}

	totalUsers, err := s.userRepo.QueryCount(tenantCtx, query.QueryOptions{})
	if err != nil {
		return nil, err
	}

	// 计算激活用户数（改为基于 CountByStatus）
	usersByStatus, err := s.userRepo.CountByStatus(tenantCtx)
	if err != nil {
		return nil, err
	}
	activeUsers := usersByStatus[svc.UserStatusActive]

	groupsByLevel, err := s.groupRepo.CountByLevel(tenantCtx)
	if err != nil {
		return nil, err
	}

	// usersByStatus 已获取

	return &svc.StatisticsResponse{
		TotalUsers:    totalUsers,
		ActiveUsers:   activeUsers,
		TotalGroups:   totalGroups,
		TotalRoles:    totalRoles,
		GroupsByLevel: groupsByLevel,
		UsersByStatus: usersByStatus,
	}, nil
}

// 私有辅助方法

// validateCreateGroupRequest 验证创建组织请求
func (s *GroupService) validateCreateGroupRequest(req *svc.CreateGroupRequest) error {
	if req.Name == "" {
		return errors.NewCode(errors.Validation, "组织名称不能为空")
	}
	if len(req.Name) > 100 {
		return errors.NewCode(errors.Validation, "组织名称不能超过100个字符")
	}
	if len(req.Description) > 500 {
		return errors.NewCode(errors.Validation, "组织描述不能超过500个字符")
	}
	return nil
}

// checkGroupNameDuplicate 检查组织名称是否重复（租户内）
func (s *GroupService) checkGroupNameDuplicate(ctx context.Context, tenantID string, name string, parentID *int64) error {
	var (
		groups []*iamentity.Group
		err    error
	)

	if parentID == nil {
		tenantCtx, bindErr := svc.BindTenantContext(ctx, tenantID)
		if bindErr != nil {
			return bindErr
		}
		groups, err = s.groupRepo.FindRootGroups(tenantCtx)
	} else {
		tenantCtx, bindErr := svc.BindTenantContext(ctx, tenantID)
		if bindErr != nil {
			return bindErr
		}
		groups, err = s.groupRepo.FindChildren(tenantCtx, *parentID)
	}

	if err != nil {
		return err
	}

	for _, group := range groups {
		if group.Name == name {
			return errors.NewCode(errors.Validation, "同一层级下组织名称不能重复")
		}
	}

	return nil
}

// buildGroupTreeNode 构建组织树节点
func (s *GroupService) buildGroupTreeNode(group *iamentity.Group) *svc.GroupTreeNode {
	if group == nil {
		return nil
	}

	node := &svc.GroupTreeNode{
		ID:          group.GetID(),
		Name:        group.Name,
		Description: group.Description,
		Level:       group.Level,
		UserCount:   len(group.Users),
	}

	for _, child := range group.Children {
		node.Children = append(node.Children, s.buildGroupTreeNode(child))
	}

	return node
}
