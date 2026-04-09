package group

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	dataquery "gochen/db/query"
	"gochen/errorx"
	"gochen/logging"
)

// GroupService 组织服务
type GroupService struct {
	groupRepo       *grouprepo.GroupRepo
	userRepo        *userrepo.UserRepo
	roleRepo        *rolerepo.RoleRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	logger          logging.ILogger
}

// NewGroupService 创建组织服务实例
func NewGroupService(
	groupRepo *grouprepo.GroupRepo,
	userRepo *userrepo.UserRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
) *GroupService {
	return &GroupService{
		groupRepo:       groupRepo,
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		scopeAuthorizer: scopeAuthorizer,
		logger:          logging.ComponentLogger("iam.service.group"),
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
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "api:group:write", tenantID); err != nil {
		return nil, err
	}

	// 2. 检查父组织是否存在（如果指定了父组织）
	var parentGroup *iamentity.Group
	if req.ParentID != nil {
		parent, err := s.groupRepo.Get(ctx, *req.ParentID)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.NotFound, "父组织不存在")
		}
		if _, err := svc.PreflightSameTenant(ctx, s.scopeAuthorizer, "", tenantID, parent.TenantID); err != nil {
			return nil, err
		}
		parentGroup = parent

		// 检查层级限制
		if parentGroup.Level >= svc.MaxGroupLevel {
			return nil, errorx.New(errorx.Validation, "组织层级不能超过10级")
		}
	}

	// 3. 检查组织名称是否重复（同一层级下，租户内）
	if err := s.checkGroupNameDuplicate(ctx, tenantID, req.Name, req.ParentID); err != nil {
		return nil, err
	}

	// 4. 创建组织实体
	group := &iamentity.Group{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
	}
	group.SetUpdatedAt(time.Now())

	// 5. 设置层级和路径
	if parentGroup != nil {
		group.SetParent(parentGroup)
	} else {
		group.Level = 1
	}

	// 6. 保存组织
	if err := s.groupRepo.Create(ctx, group); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "保存组织失败")
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
		return nil, errorx.New(errorx.Validation, "update group request is required")
	}

	// 1. 获取组织
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, "api:group:write", group.TenantID); err != nil {
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
			return nil, errorx.New(errorx.Validation, "不能将组织设置为自己的父组织")
		}
		parent, err := s.groupRepo.Get(ctx, *candidate.ParentID)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.NotFound, "父组织不存在")
		}
		if _, err := svc.PreflightSameTenant(ctx, s.scopeAuthorizer, "", group.TenantID, parent.TenantID); err != nil {
			return nil, err
		}
		if parent.Level >= svc.MaxGroupLevel {
			return nil, errorx.New(errorx.Validation, "组织层级不能超过10级")
		}
		if (*group).IsAncestorOf(parent) {
			return nil, errorx.New(errorx.Validation, "不能将组织移动到其子组织下")
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

	// 3. 保存更新
	if err := s.groupRepo.Update(ctx, group); err != nil {
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

// DeleteGroup 删除组织
func (s *GroupService) DeleteGroup(ctx context.Context, tenantID string, groupID int64) error {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireSameTenantPermission(ctx, s.scopeAuthorizer, "api:group:delete", tenantID, group.TenantID); err != nil {
		return err
	}

	// 1. 检查是否有子组织
	children, err := s.groupRepo.FindChildren(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return errorx.New(errorx.Validation, "不能删除有子组织的组织，请先处理子组织")
	}

	// 2. 检查是否有用户
	users, err := s.userRepo.FindByGroupID(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errorx.New(errorx.Validation, "不能删除有用户的组织，请先移除用户")
	}

	// 3. 删除组织
	return s.groupRepo.Delete(ctx, groupID)
}

// GetGroupTree 获取组织树
func (s *GroupService) GetGroupTree(ctx context.Context) ([]*svc.GroupTreeNode, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "api:group:read", tenantID); err != nil {
		return nil, err
	}
	groups, err := s.groupRepo.GetGroupTree(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var nodes []*svc.GroupTreeNode
	for _, group := range groups {
		nodes = append(nodes, s.buildGroupTreeNode(group))
	}
	return nodes, nil
}

// GetRootGroups 获取根组织
func (s *GroupService) GetRootGroups(ctx context.Context, tenantID string) ([]*iamentity.Group, error) {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "api:group:read", tenantID); err != nil {
		return nil, err
	}
	return s.groupRepo.FindRootGroups(ctx, tenantID)
}

// GetGroupsByLevel 根据层级获取组织
func (s *GroupService) GetGroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "api:group:read", tenantID); err != nil {
		return nil, err
	}
	return s.groupRepo.FindByLevel(ctx, tenantID, level)
}

// GetGroupUsers 获取组织用户列表
func (s *GroupService) GetGroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, "api:group:read", group.TenantID); err != nil {
		return nil, err
	}
	return s.userRepo.FindByGroupID(ctx, group.TenantID, groupID)
}

// AddUserToGroup 添加用户到组织
func (s *GroupService) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	user, err := s.userRepo.Get(ctx, userID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireSameTenantPermission(ctx, s.scopeAuthorizer, "api:group:write", user.TenantID, group.TenantID); err != nil {
		return err
	}
	return s.groupRepo.AddUserToGroup(ctx, groupID, userID)
}

// RemoveUserFromGroup 从组织移除用户
func (s *GroupService) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	user, err := s.userRepo.Get(ctx, userID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireSameTenantPermission(ctx, s.scopeAuthorizer, "api:group:write", user.TenantID, group.TenantID); err != nil {
		return err
	}
	return s.groupRepo.RemoveUserFromGroup(ctx, groupID, userID)
}

// BatchAddUsersToGroup 批量添加用户到组织（事务包裹）
func (s *GroupService) BatchAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error) {
	txCtx, err := s.groupRepo.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	txContext := txCtx.Context()
	committed := false
	defer func() {
		if !committed {
			_ = s.groupRepo.Rollback(txCtx)
		}
	}()

	response := &svc.BatchOperationResponse{}
	for _, userID := range userIDs {
		if err := s.AddUserToGroup(txContext, groupID, userID); err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, err)
		} else {
			response.SuccessCount++
		}
	}

	// 如果有任何失败，整个事务回滚，SuccessCount 置零以反映真实状态
	if response.FailureCount > 0 {
		response.SuccessCount = 0
		return response, nil
	}

	if err := s.groupRepo.Commit(txCtx); err != nil {
		return nil, err
	}
	committed = true
	return response, nil
}

// GetGroupRoles 获取组织默认角色
func (s *GroupService) GetGroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, "api:group:read", group.TenantID); err != nil {
		return nil, err
	}
	return s.roleRepo.FindByGroupID(ctx, group.TenantID, groupID)
}

// AddGroupRole 为组织添加默认角色
func (s *GroupService) AddGroupRole(ctx context.Context, groupID, roleID int64) error {
	role, err := s.roleRepo.Get(ctx, roleID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireSameTenantPermission(ctx, s.scopeAuthorizer, "api:group:write", role.TenantID, group.TenantID); err != nil {
		return err
	}
	return s.groupRepo.AddDefaultRole(ctx, groupID, roleID)
}

// RemoveGroupRole 移除组织默认角色
func (s *GroupService) RemoveGroupRole(ctx context.Context, groupID, roleID int64) error {
	role, err := s.roleRepo.Get(ctx, roleID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireSameTenantPermission(ctx, s.scopeAuthorizer, "api:group:write", role.TenantID, group.TenantID); err != nil {
		return err
	}
	return s.groupRepo.RemoveDefaultRole(ctx, groupID, roleID)
}

// GetGroupStatistics 获取组织统计信息
func (s *GroupService) GetGroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "api:group:read", tenantID); err != nil {
		return nil, err
	}

	totalGroups, err := s.groupRepo.QueryCount(ctx, dataquery.QueryOptions{
		Filters: dataquery.QueryFilters{
			"tenant_id": {{
				Op:    dataquery.FilterOpEq,
				Value: dataquery.StringValue(tenantID),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	totalRoles, err := s.roleRepo.QueryCount(ctx, dataquery.QueryOptions{
		Filters: dataquery.QueryFilters{
			"tenant_id": {{
				Op:    dataquery.FilterOpEq,
				Value: dataquery.StringValue(tenantID),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	totalUsers, err := s.userRepo.QueryCount(ctx, dataquery.QueryOptions{
		Filters: dataquery.QueryFilters{
			"tenant_id": {{
				Op:    dataquery.FilterOpEq,
				Value: dataquery.StringValue(tenantID),
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	// 计算激活用户数（改为基于 CountByStatus）
	usersByStatus, err := s.userRepo.CountByStatus(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	activeUsers := usersByStatus[svc.UserStatusActive]

	groupsByLevel, err := s.groupRepo.CountByLevel(ctx, tenantID)
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
		return errorx.New(errorx.Validation, "组织名称不能为空")
	}
	if len(req.Name) > 100 {
		return errorx.New(errorx.Validation, "组织名称不能超过100个字符")
	}
	if len(req.Description) > 500 {
		return errorx.New(errorx.Validation, "组织描述不能超过500个字符")
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
		groups, err = s.groupRepo.FindRootGroups(ctx, tenantID)
	} else {
		groups, err = s.groupRepo.FindChildren(ctx, tenantID, *parentID)
	}

	if err != nil {
		return err
	}

	for _, group := range groups {
		if group.Name == name {
			return errorx.New(errorx.Validation, "同一层级下组织名称不能重复")
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
