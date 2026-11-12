package group

import (
	"context"
	stdErrors "errors"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	appcrud "gochen/app/crud"
	"gochen/errors"
	"gochen/observe/logging"
)

var errBulkAddUsersRollback = stdErrors.New("rollback bulk add users to group")

// GroupService 组织服务
type GroupService struct {
	groupRepo                              *grouprepo.GroupRepo
	userRepo                               *userrepo.UserRepo
	roleRepo                               *rolerepo.RoleRepo
	scopeAuthorizer                        *svc.ScopeAuthorizer
	authorizer                             *svc.IAMAccess
	logger                                 logging.ILogger
	associationCommands                    map[string]*groupAssociationCommand
	statisticsCommands                     map[string]*groupStatisticsCommand
	treeCommands                           map[string]*groupTreeCommand
	readCommands                           map[string]*groupReadCommand
	roleNamespaces                         *ormrepo.Repo[*iamentity.Scope, int64]
	deleteCommands                         map[string]*groupDeleteCommand
	writeApplication, httpWriteApplication *groupWriteApplication
}

// NewGroupService 创建组织服务实例
func NewGroupService(
	groupRepo *grouprepo.GroupRepo,
	userRepo *userrepo.UserRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAccess,
	logger logging.ILogger,
) (*GroupService, error) {
	service := &GroupService{
		groupRepo:       groupRepo,
		userRepo:        userRepo,
		roleRepo:        roleRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
		logger:          logging.ComponentLogger("iam.service.group", logger),
	}
	if err := service.compileAssociationCommands(); err != nil {
		return nil, err
	}
	if err := service.compileStatisticsCommands(); err != nil {
		return nil, err
	}
	if err := service.compileTreeCommands(); err != nil {
		return nil, err
	}
	if err := service.compileReadCommands(); err != nil {
		return nil, err
	}
	if err := service.compileDeleteCommands(); err != nil {
		return nil, err
	}
	if err := service.compileWriteApplications(); err != nil {
		return nil, err
	}
	return service, nil
}

// CreateGroup 创建组织
func (s *GroupService) CreateGroup(ctx context.Context, req *svc.CreateGroupRequest) (*iamentity.Group, error) {
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
	return s.writeApplication.ExecuteNew(tenantCtx, appcrud.ActionCreate, func(context.Context) (*iamentity.Group, error) {
		return &iamentity.Group{Name: req.Name, Description: req.Description, ParentID: req.ParentID}, nil
	})
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
	return s.writeApplication.Execute(ctx, appcrud.ActionUpdate, groupID, func(_ context.Context, group *iamentity.Group) error {
		if req.Name != "" {
			group.Name = req.Name
		}
		if req.Description != "" {
			group.Description = req.Description
		}
		return svc.ApplyFieldPatches(group, patches...)
	})
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
	return s.writeApplication.Delete(tenantCtx, groupID)
}

// ValidateDelete 检查组织是否允许删除（检查是否有子组织和用户）。
func (s *GroupService) ValidateDelete(ctx context.Context, groupID int64) error {
	_, err := s.deleteCommands["validate_delete"].Execute(ctx, groupID)
	return err
}

// GroupTree 获取组织树
func (s *GroupService) GroupTree(ctx context.Context) ([]*svc.GroupTreeNode, error) {
	return s.treeCommands["tree"].Execute(ctx, struct{}{})
}

// RootGroups 获取根组织
func (s *GroupService) RootGroups(ctx context.Context, tenantID string) ([]*iamentity.Group, error) {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out, err := s.executeRead(tenantCtx, "roots", GroupReadInput{})
	return out.Groups, err
}

// GroupsByLevel 根据层级获取组织
func (s *GroupService) GroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	out, err := s.executeRead(ctx, "by_level", GroupReadInput{Level: level})
	return out.Groups, err
}

// GroupUsers 获取组织用户列表
func (s *GroupService) GroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	out, err := s.executeRead(ctx, "users", GroupReadInput{ID: groupID})
	return out.Users, err
}

// AddUserToGroup 添加用户到组织
func (s *GroupService) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	_, err := s.executeAssociation(ctx, "add_user", GroupAssociationInput{ID: groupID, RelatedIDs: []int64{userID}})
	return err
}

// RemoveUserFromGroup 从组织移除用户
func (s *GroupService) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	_, err := s.executeAssociation(ctx, "remove_user", GroupAssociationInput{ID: groupID, RelatedIDs: []int64{userID}})
	return err
}

// BulkAddUsersToGroup 批量添加用户到组织（事务包裹）
func (s *GroupService) BulkAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BulkOperationResponse, error) {
	return s.executeAssociation(ctx, "bulk_add_users", GroupAssociationInput{ID: groupID, RelatedIDs: userIDs})
}

// GroupRoles 获取组织默认角色
func (s *GroupService) GroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	out, err := s.executeRead(ctx, "roles", GroupReadInput{ID: groupID})
	return out.Roles, err
}

// AddGroupRole 为组织添加默认角色
func (s *GroupService) AddGroupRole(ctx context.Context, groupID, roleID int64) error {
	_, err := s.executeAssociation(ctx, "add_role", GroupAssociationInput{ID: groupID, RelatedIDs: []int64{roleID}})
	return err
}

// RemoveGroupRole 移除组织默认角色
func (s *GroupService) RemoveGroupRole(ctx context.Context, groupID, roleID int64) error {
	_, err := s.executeAssociation(ctx, "remove_role", GroupAssociationInput{ID: groupID, RelatedIDs: []int64{roleID}})
	return err
}

// GroupStatistics 获取组织统计信息
func (s *GroupService) GroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error) {
	return s.statisticsCommands["statistics"].Execute(ctx, struct{}{})
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
