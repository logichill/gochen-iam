package group

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen/errorx"
	"gochen/logging"
)

// GroupService 组织服务
type GroupService struct {
	groupRepo *grouprepo.GroupRepo
	userRepo  *userrepo.UserRepo
	roleRepo  *rolerepo.RoleRepo
	logger    logging.ILogger
}

// NewGroupService 创建组织服务实例
func NewGroupService(
	groupRepo *grouprepo.GroupRepo,
	userRepo *userrepo.UserRepo,
	roleRepo *rolerepo.RoleRepo,
) *GroupService {
	return &GroupService{
		groupRepo: groupRepo,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		logger:    logging.ComponentLogger("iam.service.group"),
	}
}

// CreateGroup 创建组织
func (s *GroupService) CreateGroup(ctx context.Context, req *svc.CreateGroupRequest) (*iamentity.Group, error) {
	// 1. 验证请求数据
	if err := s.validateCreateGroupRequest(req); err != nil {
		return nil, err
	}

	// 2. 检查父组织是否存在（如果指定了父组织）
	var parentGroup *iamentity.Group
	if req.ParentID != nil {
		parent, err := s.groupRepo.Get(ctx, *req.ParentID)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.NotFound, "父组织不存在")
		}
		parentGroup = parent

		// 检查层级限制
		if parentGroup.Level >= svc.MaxGroupLevel {
			return nil, errorx.New(errorx.Validation, "组织层级不能超过10级")
		}
	}

	// 3. 检查组织名称是否重复（同一层级下）
	if err := s.checkGroupNameDuplicate(ctx, req.Name, req.ParentID); err != nil {
		return nil, err
	}

	// 4. 创建组织实体
	group := &iamentity.Group{
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

// UpdateGroup 更新组织
func (s *GroupService) UpdateGroup(ctx context.Context, groupID int64, req *svc.UpdateGroupRequest) (*iamentity.Group, error) {
	// 1. 获取组织
	group, err := s.groupRepo.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}

	targetParentID := (*group).ParentID
	parentChanged := req.ParentIDSet && !sameParentID((*group).ParentID, req.ParentID)
	if req.ParentIDSet {
		targetParentID = req.ParentID
	}
	targetName := (*group).Name
	if req.Name != "" {
		targetName = req.Name
	}

	if parentChanged || targetName != (*group).Name {
		if err := s.checkGroupNameDuplicate(ctx, targetName, targetParentID); err != nil {
			return nil, err
		}
	}

	// 2. 更新字段
	if req.Name != "" && req.Name != (*group).Name {
		(*group).Name = req.Name
	}

	if req.Description != "" {
		(*group).Description = req.Description
	}
	if parentChanged && req.ParentID != nil {
		if *req.ParentID == (*group).GetID() {
			return nil, errorx.New(errorx.Validation, "不能将组织设置为自己的父组织")
		}
		parent, err := s.groupRepo.Get(ctx, *req.ParentID)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.NotFound, "父组织不存在")
		}
		if parent.Level >= svc.MaxGroupLevel {
			return nil, errorx.New(errorx.Validation, "组织层级不能超过10级")
		}
		if (*group).IsAncestorOf(parent) {
			return nil, errorx.New(errorx.Validation, "不能将组织移动到其子组织下")
		}
		(*group).SetParent(parent)
	} else if parentChanged && req.ParentID == nil {
		(*group).SetParent(nil)
	}

	(*group).SetUpdatedAt(time.Now())

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
func (s *GroupService) DeleteGroup(ctx context.Context, groupID int64) error {
	// 1. 检查是否有子组织
	children, err := s.groupRepo.FindChildren(ctx, groupID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return errorx.New(errorx.Validation, "不能删除有子组织的组织，请先处理子组织")
	}

	// 2. 检查是否有用户
	users, err := s.userRepo.FindByGroupID(ctx, groupID)
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
	groups, err := s.groupRepo.GetGroupTree(ctx)
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
func (s *GroupService) GetRootGroups(ctx context.Context) ([]*iamentity.Group, error) {
	return s.groupRepo.FindRootGroups(ctx)
}

// GetGroupsByLevel 根据层级获取组织
func (s *GroupService) GetGroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	return s.groupRepo.FindByLevel(ctx, level)
}

// GetGroupUsers 获取组织用户列表
func (s *GroupService) GetGroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	return s.userRepo.FindByGroupID(ctx, groupID)
}

// AddUserToGroup 添加用户到组织
func (s *GroupService) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	// 确认用户存在
	if _, err := s.userRepo.Get(ctx, userID); err != nil {
		return err
	}
	// 确认组织存在
	if _, err := s.groupRepo.Get(ctx, groupID); err != nil {
		return err
	}
	return s.groupRepo.AddUserToGroup(ctx, groupID, userID)
}

// RemoveUserFromGroup 从组织移除用户
func (s *GroupService) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	return s.groupRepo.RemoveUserFromGroup(ctx, groupID, userID)
}

// BatchAddUsersToGroup 批量添加用户到组织
func (s *GroupService) BatchAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error) {
	response := &svc.BatchOperationResponse{}

	for _, userID := range userIDs {
		if err := s.AddUserToGroup(ctx, groupID, userID); err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, err)
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// GetGroupRoles 获取组织默认角色
func (s *GroupService) GetGroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	return s.roleRepo.FindByGroupID(ctx, groupID)
}

// AddGroupRole 为组织添加默认角色
func (s *GroupService) AddGroupRole(ctx context.Context, groupID, roleID int64) error {
	// 确认角色存在
	if _, err := s.roleRepo.Get(ctx, roleID); err != nil {
		return err
	}
	// 确认组织存在
	if _, err := s.groupRepo.Get(ctx, groupID); err != nil {
		return err
	}
	return s.groupRepo.AddDefaultRole(ctx, groupID, roleID)
}

// RemoveGroupRole 移除组织默认角色
func (s *GroupService) RemoveGroupRole(ctx context.Context, groupID, roleID int64) error {
	return s.groupRepo.RemoveDefaultRole(ctx, groupID, roleID)
}

// GetGroupStatistics 获取组织统计信息
func (s *GroupService) GetGroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error) {
	totalGroups, err := s.groupRepo.Count(ctx)
	if err != nil {
		return nil, err
	}

	totalRoles, err := s.roleRepo.Count(ctx)
	if err != nil {
		return nil, err
	}

	totalUsers, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, err
	}

	// 计算激活用户数（改为基于 CountByStatus）
	usersByStatus, err := s.userRepo.CountByStatus(ctx)
	if err != nil {
		return nil, err
	}
	activeUsers := usersByStatus[svc.UserStatusActive]

	groupsByLevel, err := s.groupRepo.CountByLevel(ctx)
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

// checkGroupNameDuplicate 检查组织名称是否重复
func (s *GroupService) checkGroupNameDuplicate(ctx context.Context, name string, parentID *int64) error {
	var (
		groups []*iamentity.Group
		err    error
	)

	if parentID == nil {
		groups, err = s.groupRepo.FindRootGroups(ctx)
	} else {
		groups, err = s.groupRepo.FindChildren(ctx, *parentID)
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
