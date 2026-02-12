package role

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	iamevent "gochen-iam/event"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen/errorx"
	"gochen/eventing"
	"gochen/eventing/bus"
	"gochen/logging"
)

// RoleService 角色服务
type RoleService struct {
	roleRepo  *rolerepo.RoleRepo
	userRepo  *userrepo.UserRepo
	groupRepo *grouprepo.GroupRepo
	eventBus  bus.IEventBus
	logger    logging.ILogger
}

// NewRoleService 创建角色服务实例
func NewRoleService(
	roleRepo *rolerepo.RoleRepo,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	eventBus bus.IEventBus,
) *RoleService {
	return &RoleService{
		roleRepo:  roleRepo,
		userRepo:  userRepo,
		groupRepo: groupRepo,
		eventBus:  eventBus,
		logger:    logging.ComponentLogger("iam.service.role"),
	}
}

// CreateRole 创建角色
func (s *RoleService) CreateRole(ctx context.Context, req *svc.CreateRoleRequest) (*iamentity.Role, error) {
	// 1. 验证请求数据
	if err := s.validateCreateRoleRequest(req); err != nil {
		return nil, err
	}

	// 2. 检查角色名称是否已存在
	existingRole, err := s.roleRepo.FindByName(ctx, req.Name)
	if err != nil && !errorx.Is(err, errorx.NotFound) {
		return nil, errorx.Wrap(err, errorx.Database, "检查角色名称失败")
	}
	if existingRole != nil {
		return nil, errorx.New(errorx.Validation, "角色名称已存在")
	}

	// 3. 验证权限
	if err := s.validatePermissions(req.Permissions); err != nil {
		return nil, err
	}

	// 4. 创建角色实体
	role := &iamentity.Role{
		Code:        req.Name, // 当前阶段默认使用名称作为稳定编码
		Name:        req.Name,
		Description: req.Description,
		Permissions: iamentity.PermissionArray(req.Permissions),
		IsSystem:    false,
		Status:      svc.RoleStatusActive,
	}
	role.SetUpdatedAt(time.Now())

	// 5. 保存角色
	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "保存角色失败")
	}

	return role, nil
}

// UpdateRole 更新角色
func (s *RoleService) UpdateRole(ctx context.Context, roleID int64, req *svc.UpdateRoleRequest) (*iamentity.Role, error) {
	// 1. 获取角色
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return nil, errorx.New(errorx.Validation, "系统角色不能被修改")
	}

	// 3. 更新字段
	if req.Name != "" && req.Name != role.Name {
		// 检查名称是否重复
		existingRole, err := s.roleRepo.FindByName(ctx, req.Name)
		if err != nil && !errorx.Is(err, errorx.NotFound) {
			return nil, errorx.Wrap(err, errorx.Database, "检查角色名称失败")
		}
		if existingRole != nil && existingRole.GetID() != roleID {
			return nil, errorx.New(errorx.Validation, "角色名称已存在")
		}
		role.Name = req.Name
	}

	if req.Description != "" {
		role.Description = req.Description
	}

	if len(req.Permissions) > 0 {
		if err := s.validatePermissions(req.Permissions); err != nil {
			return nil, err
		}
		role.SetPermissions(req.Permissions)
	}

	role.SetUpdatedAt(time.Now())

	// 4. 保存更新
	if err := s.roleRepo.Update(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

// DeleteRole 删除角色
func (s *RoleService) DeleteRole(ctx context.Context, roleID int64) error {
	// 1. 获取角色
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return errorx.New(errorx.Validation, "系统角色不能被删除")
	}

	// 3. 检查是否正在使用中
	if role.IsInUse() {
		return errorx.New(errorx.Validation, "角色正在使用中，不能删除")
	}

	// 4. 删除角色
	return s.roleRepo.Delete(ctx, roleID)
}

// AssignRoleToUser 将角色分配给用户
func (s *RoleService) AssignRoleToUser(ctx context.Context, roleID, userID int64) error {
	// 1. 检查角色是否存在
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 检查角色是否激活
	if role.Status != svc.RoleStatusActive {
		return errorx.New(errorx.Validation, "只能分配激活状态的角色")
	}

	// 3. 检查用户是否存在
	_, err = s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 4. 分配角色
	if err := s.roleRepo.AssignToUser(ctx, roleID, userID); err != nil {
		return err
	}

	// 5. 发布用户角色分配事件（最佳努力，不影响主流程）
	s.publishUserRoleAssignedEvent(ctx, userID, role)
	return nil
}

// RemoveRoleFromUser 从用户移除角色
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, roleID, userID int64) error {
	if err := s.roleRepo.RemoveFromUser(ctx, roleID, userID); err != nil {
		return err
	}

	// 发布用户角色移除事件（最佳努力）
	s.publishUserRoleRemovedEvent(ctx, userID, roleID)
	return nil
}

// AssignRoleToGroup 将角色分配给组织作为默认角色
func (s *RoleService) AssignRoleToGroup(ctx context.Context, roleID, groupID int64) error {
	// 1. 检查角色是否存在
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 检查角色是否激活
	if role.Status != svc.RoleStatusActive {
		return errorx.New(errorx.Validation, "只能分配激活状态的角色")
	}

	// 3. 检查组织是否存在
	_, err = s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// 4. 分配角色给组织
	return s.roleRepo.AssignToGroup(ctx, roleID, groupID)
}

// RemoveRoleFromGroup 从组织移除默认角色
func (s *RoleService) RemoveRoleFromGroup(ctx context.Context, roleID, groupID int64) error {
	return s.roleRepo.RemoveFromGroup(ctx, roleID, groupID)
}

// AddPermission 为角色添加权限
func (s *RoleService) AddPermission(ctx context.Context, roleID int64, permission string) error {
	// 1. 获取角色
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return errorx.New(errorx.Validation, "系统角色权限不能被修改")
	}

	// 3. 验证权限
	if err := s.validatePermissions([]string{permission}); err != nil {
		return err
	}

	// 4. 添加权限
	role.AddPermission(permission)
	return s.roleRepo.Update(ctx, role)
}

// RemovePermission 从角色移除权限
func (s *RoleService) RemovePermission(ctx context.Context, roleID int64, permission string) error {
	// 1. 获取角色
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return errorx.New(errorx.Validation, "系统角色权限不能被修改")
	}

	// 3. 移除权限
	role.RemovePermission(permission)
	return s.roleRepo.Update(ctx, role)
}

// ActivateRole 激活角色
func (s *RoleService) ActivateRole(ctx context.Context, roleID int64) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	role.Activate()
	return s.roleRepo.Update(ctx, role)
}

// DeactivateRole 停用角色
func (s *RoleService) DeactivateRole(ctx context.Context, roleID int64) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return errorx.New(errorx.Validation, "系统角色不能被停用")
	}

	role.Deactivate()
	return s.roleRepo.Update(ctx, role)
}

// CloneRole 克隆角色
func (s *RoleService) CloneRole(ctx context.Context, roleID int64, newName string) (*iamentity.Role, error) {
	// 1. 获取原角色
	originalRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}

	// 2. 检查新名称是否重复
	existingRole, err := s.roleRepo.FindByName(ctx, newName)
	if err != nil && !errorx.Is(err, errorx.NotFound) {
		return nil, errorx.Wrap(err, errorx.Database, "检查角色名称失败")
	}
	if existingRole != nil {
		return nil, errorx.New(errorx.Validation, "角色名称已存在")
	}

	// 3. 克隆角色
	clonedRole := originalRole.Clone(newName)
	if clonedRole.Code == "" {
		clonedRole.Code = newName
	}

	// 4. 保存克隆的角色
	if err := s.roleRepo.Create(ctx, clonedRole); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "保存克隆角色失败")
	}

	return clonedRole, nil
}

// GetRoleUsers 获取拥有指定角色的用户
func (s *RoleService) GetRoleUsers(ctx context.Context, roleID int64) ([]*iamentity.User, error) {
	return s.userRepo.FindByRoleID(ctx, roleID)
}

// GetRoleGroups 获取使用指定角色作为默认角色的组织
func (s *RoleService) GetRoleGroups(ctx context.Context, roleID int64) ([]*iamentity.Group, error) {
	return s.groupRepo.FindByDefaultRoleID(ctx, roleID)
}

// CheckPermission 检查权限
func (s *RoleService) CheckPermission(ctx context.Context, req *svc.PermissionCheckRequest) (*svc.PermissionCheckResponse, error) {
	// 1. 获取用户
	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	// 2. 检查权限
	hasPermission := user.HasPermission(req.Permission)

	// 3. 获取用户角色
	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	return &svc.PermissionCheckResponse{
		HasPermission: hasPermission,
		Roles:         roles,
		Source:        "direct", // 简化实现，实际可以区分直接权限和继承权限
	}, nil
}

// SearchRoles 搜索角色
func (s *RoleService) SearchRoles(ctx context.Context, keyword string, limit int) ([]*iamentity.Role, error) {
	return s.roleRepo.SearchRoles(ctx, keyword, limit)
}

// GetActiveRoles 获取激活状态的角色
func (s *RoleService) GetActiveRoles(ctx context.Context) ([]*iamentity.Role, error) {
	return s.roleRepo.FindByStatus(ctx, svc.RoleStatusActive)
}

// GetSystemRoles 获取系统角色
func (s *RoleService) GetSystemRoles(ctx context.Context) ([]*iamentity.Role, error) {
	return s.roleRepo.FindSystemRoles(ctx)
}

// InitializeSystemRoles 初始化系统角色
func (s *RoleService) InitializeSystemRoles(ctx context.Context) error {
	return s.roleRepo.InitializeSystemRoles(ctx)
}

// GetRoleStatistics 获取角色统计信息
func (s *RoleService) GetRoleStatistics(ctx context.Context) (map[string]interface{}, error) {
	// 1. 统计总角色数
	totalRoles, err := s.roleRepo.Count(ctx)
	if err != nil {
		return nil, err
	}

	// 2. 统计激活角色数
	activeRoles, err := s.roleRepo.FindByStatus(ctx, svc.RoleStatusActive)
	if err != nil {
		return nil, err
	}

	// 3. 统计系统角色数
	systemRoles, err := s.roleRepo.FindSystemRoles(ctx)
	if err != nil {
		return nil, err
	}

	// 4. 统计各状态角色数
	statusCounts, err := s.roleRepo.CountByStatus(ctx)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_roles":     totalRoles,
		"active_roles":    len(activeRoles),
		"system_roles":    len(systemRoles),
		"roles_by_status": statusCounts,
	}, nil
}

// BatchAssignRole 批量分配角色
func (s *RoleService) BatchAssignRole(ctx context.Context, req *svc.RoleAssignRequest) (*svc.BatchOperationResponse, error) {
	response := &svc.BatchOperationResponse{}

	for _, userID := range req.UserIDs {
		if err := s.AssignRoleToUser(ctx, req.RoleID, userID); err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, err)
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// 私有辅助方法

// validateCreateRoleRequest 验证创建角色请求
func (s *RoleService) validateCreateRoleRequest(req *svc.CreateRoleRequest) error {
	if req.Name == "" {
		return errorx.New(errorx.Validation, "角色名称不能为空")
	}
	if len(req.Name) > 50 {
		return errorx.New(errorx.Validation, "角色名称不能超过50个字符")
	}
	if len(req.Description) > 500 {
		return errorx.New(errorx.Validation, "角色描述不能超过500个字符")
	}
	if len(req.Permissions) == 0 {
		return errorx.New(errorx.Validation, "角色必须至少拥有一个权限")
	}
	return nil
}

// validatePermissions 验证权限列表
func (s *RoleService) validatePermissions(permissions []string) error {
	for _, permission := range permissions {
		if !iammw.IsValidPermissionCode(permission) {
			return errorx.New(errorx.Validation, "无效的权限: "+permission)
		}
	}

	// 严格权限字典：仅允许“系统已声明的权限”（由 PermissionMiddleware 自动收集）。
	if err := iammw.EnsureStrictPermissionRegistryLoaded(); err != nil {
		return err
	}
	for _, p := range permissions {
		if !iammw.HasRequiredPermission(p) {
			return errorx.New(errorx.Validation, "未知权限: "+p)
		}
	}
	return nil
}

// 发布用户角色相关事件（内部辅助方法）

func (s *RoleService) publishUserRoleAssignedEvent(ctx context.Context, userID int64, role *iamentity.Role) {
	if s.eventBus == nil || role == nil {
		return
	}

	payload := &iamevent.UserRoleAssigned{
		UserID:     userID,
		RoleID:     role.GetID(),
		RoleCode:   role.Code,
		AssignedAt: time.Now(),
	}

	evt := eventing.NewEvent(userID, "user", payload.GetType(), 1, payload)
	if err := s.eventBus.PublishEvent(ctx, evt); err != nil {
		s.logger.Warn(ctx, "[RoleService] 发布 UserRoleAssigned 事件失败",
			logging.Error(err),
			logging.Int64("user_id", userID),
			logging.Int64("role_id", role.GetID()),
			logging.String("role_code", role.Code),
		)
	}
}

func (s *RoleService) publishUserRoleRemovedEvent(ctx context.Context, userID, roleID int64) {
	if s.eventBus == nil {
		return
	}

	payload := &iamevent.UserRoleRemoved{
		UserID:    userID,
		RoleID:    roleID,
		RemovedAt: time.Now(),
	}

	evt := eventing.NewEvent(userID, "user", payload.GetType(), 1, payload)
	if err := s.eventBus.PublishEvent(ctx, evt); err != nil {
		s.logger.Warn(ctx, "[RoleService] 发布 UserRoleRemoved 事件失败",
			logging.Error(err),
			logging.Int64("user_id", userID),
			logging.Int64("role_id", roleID),
		)
	}
}
