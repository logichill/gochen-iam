package role

import (
	"context"
	stdErrors "errors"
	"time"

	iamentity "gochen-iam/entity"
	iamevent "gochen-iam/event"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	appcrud "gochen/app/crud"
	auth "gochen/auth"
	"gochen/db/query"
	"gochen/errors"
	"gochen/eventing"
	"gochen/eventing/bus"
	"gochen/ident"
	"gochen/logging"
)

var errBatchAssignRoleRollback = stdErrors.New("rollback batch assign role")

// RoleService 角色服务
type RoleService struct {
	roleRepo         *rolerepo.RoleRepo
	userRepo         *userrepo.UserRepo
	groupRepo        *grouprepo.GroupRepo
	scopeAuthorizer  *svc.ScopeAuthorizer
	authorizer       auth.IAuthorizer
	eventBus         bus.IEventBus
	eventIDGenerator ident.IGenerator[string]
	logger           logging.ILogger
	governance       *Governance
}

// NewRoleService 创建角色服务实例
func NewRoleService(
	roleRepo *rolerepo.RoleRepo,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *auth.Authorizer,
	eventBus bus.IEventBus,
) *RoleService {
	return &RoleService{
		roleRepo:         roleRepo,
		userRepo:         userRepo,
		groupRepo:        groupRepo,
		scopeAuthorizer:  scopeAuthorizer,
		authorizer:       authorizer,
		eventBus:         eventBus,
		eventIDGenerator: eventing.DefaultEventIDGenerator(),
		logger:           logging.ComponentLogger("iam.service.role"),
		governance:       NewGovernance(roleRepo, userRepo, scopeAuthorizer),
	}
}

// Governance 返回角色治理规则聚合器。
func (s *RoleService) Governance() *Governance {
	if s == nil {
		return nil
	}
	return s.governance
}

// CreateRole 创建角色。
func (s *RoleService) CreateRole(ctx context.Context, req *svc.CreateRoleRequest) (*iamentity.Role, error) {
	// 1. 验证请求数据
	if err := s.validateCreateRoleRequest(req); err != nil {
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
	namespaceScope, err := s.resolveTenantScope(tenantCtx, tenantID)
	if err != nil {
		return nil, err
	}
	if namespaceScope != nil {
		tenantCtx, err = svc.BindManagedScopeContext(tenantCtx, namespaceScope.ID)
		if err != nil {
			return nil, err
		}
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), &iamentity.Role{TenantID: tenantID})
	if err != nil {
		return nil, err
	}

	// 2. 创建角色实体
	role := &iamentity.Role{
		TenantID:         tenantID,
		OwnerID:          svc.TenantOwnerID(tenantID),
		NamespaceScopeID: namespaceScope.ID,
		Code:             req.Name, // 当前阶段默认使用名称作为稳定编码
		Name:             req.Name,
		Description:      req.Description,
		Permissions:      iamentity.PermissionArray(req.Permissions),
		IsSystem:         false,
		Status:           svc.RoleStatusActive,
	}

	if err := s.governance.PrepareCreate(tenantCtx, role); err != nil {
		return nil, err
	}

	// 3. 保存角色
	if err := s.roleRepo.CreateWithConstraint(tenantCtx, role, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "保存角色失败")
	}

	return role, nil
}

// UpdateRole 更新角色。
func (s *RoleService) UpdateRole(ctx context.Context, roleID int64, req *svc.UpdateRoleRequest) (*iamentity.Role, error) {
	// 1. 获取角色
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return nil, err
	}
	current := currentRoleSnapshot(role)
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role)
	if err != nil {
		return nil, err
	}

	// 2. 更新字段
	if req.Name != "" && req.Name != role.Name {
		role.Name = req.Name
	}

	if req.Description != "" {
		role.Description = req.Description
	}

	if len(req.Permissions) > 0 {
		role.SetPermissions(req.Permissions)
	}

	if err := s.governance.PrepareUpdateWithCurrent(tenantCtx, current, role); err != nil {
		return nil, err
	}

	// 3. 保存更新
	if err := s.roleRepo.UpdateWithConstraint(tenantCtx, role, guard); err != nil {
		return nil, err
	}

	return role, nil
}

// DeleteRole 删除角色。
func (s *RoleService) DeleteRole(ctx context.Context, roleID int64) error {
	// 1. 获取角色
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionDelete), role)
	if err != nil {
		return err
	}

	if err := s.governance.ValidateDeleteWithRole(tenantCtx, role); err != nil {
		return err
	}

	// 3. 删除角色
	return s.roleRepo.DeleteWithConstraint(tenantCtx, roleID, guard)
}

// AssignRoleToUser 将角色分配给用户
func (s *RoleService) AssignRoleToUser(ctx context.Context, roleID, userID int64) error {
	// 1. 检查角色是否存在
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	user, err := s.userRepo.Get(tenantCtx, userID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role, user)
	if err != nil {
		return err
	}

	// 2. 检查角色是否激活
	if role.Status != svc.RoleStatusActive {
		return errors.NewCode(errors.Validation, "只能分配激活状态的角色")
	}

	// 4. 分配角色
	if err := s.roleRepo.AssignToUserWithConstraint(tenantCtx, roleID, userID, guard); err != nil {
		return err
	}

	// 5. 发布用户角色分配事件（最佳努力，不影响主流程）
	s.publishUserRoleAssignedEvent(ctx, userID, role)
	return nil
}

// RemoveRoleFromUser 从用户移除角色
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, roleID, userID int64) error {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	user, err := s.userRepo.Get(tenantCtx, userID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role, user)
	if err != nil {
		return err
	}
	if err := s.roleRepo.RemoveFromUserWithConstraint(tenantCtx, roleID, userID, guard); err != nil {
		return err
	}

	// 发布用户角色移除事件（最佳努力）
	s.publishUserRoleRemovedEvent(ctx, userID, roleID)
	return nil
}

// AssignRoleToGroup 将角色分配给组织作为默认角色
func (s *RoleService) AssignRoleToGroup(ctx context.Context, roleID, groupID int64) error {
	// 1. 检查角色是否存在
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(tenantCtx, groupID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role, group)
	if err != nil {
		return err
	}

	// 2. 检查角色是否激活
	if role.Status != svc.RoleStatusActive {
		return errors.NewCode(errors.Validation, "只能分配激活状态的角色")
	}

	// 4. 分配角色给组织
	return s.roleRepo.AssignToGroupWithConstraint(tenantCtx, roleID, groupID, guard)
}

// RemoveRoleFromGroup 从组织移除默认角色
func (s *RoleService) RemoveRoleFromGroup(ctx context.Context, roleID, groupID int64) error {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(tenantCtx, groupID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role, group)
	if err != nil {
		return err
	}
	return s.roleRepo.RemoveFromGroupWithConstraint(tenantCtx, roleID, groupID, guard)
}

// AddPermission 为角色添加权限
func (s *RoleService) AddPermission(ctx context.Context, roleID int64, permission string) error {
	// 1. 获取角色
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色权限不能被修改")
	}

	// 3. 验证权限
	namespaceScope, err := s.resolveRoleNamespaceScope(tenantCtx, role)
	if err != nil {
		return err
	}
	if err := s.validatePermissionsForScope([]string{permission}, namespaceScope); err != nil {
		return err
	}
	// 4. 添加权限
	role.AddPermission(permission)
	return s.roleRepo.UpdateWithConstraint(tenantCtx, role, guard)
}

// RemovePermission 从角色移除权限
func (s *RoleService) RemovePermission(ctx context.Context, roleID int64, permission string) error {
	// 1. 获取角色
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统角色
	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色权限不能被修改")
	}

	// 3. 移除权限
	role.RemovePermission(permission)
	return s.roleRepo.UpdateWithConstraint(tenantCtx, role, guard)
}

// ActivateRole 激活角色
func (s *RoleService) ActivateRole(ctx context.Context, roleID int64) error {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role)
	if err != nil {
		return err
	}

	role.Activate()
	return s.roleRepo.UpdateWithConstraint(tenantCtx, role, guard)
}

// DeactivateRole 停用角色
func (s *RoleService) DeactivateRole(ctx context.Context, roleID int64) error {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色不能被停用")
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), role)
	if err != nil {
		return err
	}

	role.Deactivate()
	return s.roleRepo.UpdateWithConstraint(tenantCtx, role, guard)
}

// CloneRole 克隆角色
func (s *RoleService) CloneRole(ctx context.Context, roleID int64, newName string) (*iamentity.Role, error) {
	// 1. 获取原角色
	originalRole, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return nil, err
	}

	// 2. 检查新名称是否重复
	existingRole, err := s.roleRepo.FindByName(tenantCtx, newName)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return nil, errors.Wrap(err, errors.Database, "检查角色名称失败")
	}
	if existingRole != nil {
		return nil, errors.NewCode(errors.Validation, "角色名称已存在")
	}

	// 3. 克隆角色
	clonedRole := originalRole.Clone(newName)
	clonedRole.TenantID = originalRole.TenantID
	clonedRole.NamespaceScopeID = originalRole.NamespaceScopeID
	if err := s.governance.PrepareCreate(tenantCtx, clonedRole); err != nil {
		return nil, err
	}

	// 4. 保存克隆的角色
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), clonedRole)
	if err != nil {
		return nil, err
	}
	if err := s.roleRepo.CreateWithConstraint(tenantCtx, clonedRole, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "保存克隆角色失败")
	}

	return clonedRole, nil
}

// RoleUsers 获取拥有指定角色的用户
func (s *RoleService) RoleUsers(ctx context.Context, roleID int64) ([]*iamentity.User, error) {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), role.TenantID); err != nil {
		return nil, err
	}
	return s.userRepo.FindByRoleID(tenantCtx, roleID)
}

// RoleGroups 获取使用指定角色作为默认角色的组织
func (s *RoleService) RoleGroups(ctx context.Context, roleID int64) ([]*iamentity.Group, error) {
	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.roleRepo, roleID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), role.TenantID); err != nil {
		return nil, err
	}
	return s.groupRepo.FindByDefaultRoleID(tenantCtx, roleID)
}

// CheckPermission 检查权限
func (s *RoleService) CheckPermission(ctx context.Context, req *svc.PermissionCheckRequest) (*svc.PermissionCheckResponse, error) {
	// 1. 获取用户
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, req.UserID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.PreflightTenant(ctx, s.scopeAuthorizer, user.TenantID, ""); err != nil {
		return nil, err
	}

	// 2. 按有效角色求值，包含 group 默认角色链路
	roles, permissions, err := svc.ResolveEffectiveRoleNamesAndPermissionsForUser(
		tenantCtx,
		req.UserID,
		s.roleRepo,
		s.groupRepo,
	)
	if err != nil {
		return nil, err
	}
	hasPermission := (auth.Principal{Permissions: permissions}).AllowsPermission(req.Permission)

	return &svc.PermissionCheckResponse{
		HasPermission: hasPermission,
		Roles:         roles,
		Source:        "effective",
	}, nil
}

// SearchRoles 搜索角色
func (s *RoleService) SearchRoles(ctx context.Context, keyword string, limit int) ([]*iamentity.Role, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.roleRepo.SearchRoles(tenantCtx, keyword, limit)
}

// ActiveRoles 获取激活状态的角色
func (s *RoleService) ActiveRoles(ctx context.Context) ([]*iamentity.Role, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.roleRepo.FindByStatus(tenantCtx, svc.RoleStatusActive)
}

// SystemRoles 获取系统角色
func (s *RoleService) SystemRoles(ctx context.Context) ([]*iamentity.Role, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.roleRepo.FindSystemRoles(tenantCtx)
}

// InitializeSystemRoles 初始化系统角色（租户维度）
func (s *RoleService) InitializeSystemRoles(ctx context.Context, tenantID string) error {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionWrite), tenantID); err != nil {
		return err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	namespaceScope, err := s.resolveTenantScope(tenantCtx, tenantID)
	if err != nil {
		return err
	}
	return s.initializeBuiltinRoles(tenantCtx, tenantID, namespaceScope)
}

// RoleStatistics 返回角色统计信息。
func (s *RoleService) RoleStatistics(ctx context.Context) (map[string]interface{}, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// 1. 统计总角色数
	totalRoles, err := s.roleRepo.QueryCount(tenantCtx, query.QueryOptions{})
	if err != nil {
		return nil, err
	}

	// 2. 统计激活角色数
	activeRoles, err := s.roleRepo.FindByStatus(tenantCtx, svc.RoleStatusActive)
	if err != nil {
		return nil, err
	}

	// 3. 统计系统角色数
	systemRoles, err := s.roleRepo.FindSystemRoles(tenantCtx)
	if err != nil {
		return nil, err
	}

	// 4. 统计各状态角色数
	statusCounts, err := s.roleRepo.CountByStatus(tenantCtx)
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

// BatchAssignRole 批量分配角色（事务包裹）
func (s *RoleService) BatchAssignRole(ctx context.Context, req *svc.RoleAssignRequest) (*svc.BatchOperationResponse, error) {
	response := &svc.BatchOperationResponse{}
	err := appcrud.WithTx(ctx, s.roleRepo, func(txCtx context.Context) error {
		for _, userID := range req.UserIDs {
			if err := s.AssignRoleToUser(txCtx, req.RoleID, userID); err != nil {
				response.FailureCount++
				response.Errors = append(response.Errors, err)
			} else {
				response.SuccessCount++
			}
		}
		if response.FailureCount > 0 {
			response.SuccessCount = 0
			return errBatchAssignRoleRollback
		}
		return nil
	})
	if err != nil && !stdErrors.Is(err, errBatchAssignRoleRollback) {
		return nil, err
	}

	// 如果有任何失败，整个事务回滚，SuccessCount 置零以反映真实状态
	if response.FailureCount > 0 {
		return response, nil
	}
	return response, nil
}

// 私有辅助方法

// validateCreateRoleRequest 验证创建角色请求
func (s *RoleService) validateCreateRoleRequest(req *svc.CreateRoleRequest) error {
	if req.Name == "" {
		return errors.NewCode(errors.Validation, "角色名称不能为空")
	}
	if len(req.Name) > 50 {
		return errors.NewCode(errors.Validation, "角色名称不能超过50个字符")
	}
	if len(req.Description) > 500 {
		return errors.NewCode(errors.Validation, "角色描述不能超过500个字符")
	}
	if len(req.Permissions) == 0 {
		return errors.NewCode(errors.Validation, "角色必须至少拥有一个权限")
	}
	return nil
}

// validatePermissions 验证权限列表
func (s *RoleService) validatePermissions(permissions []string) error {
	return validatePermissions(permissions)
}

func (s *RoleService) validatePermissionsForScope(permissions []string, namespaceScope *iamentity.Scope) error {
	return validatePermissionsForScope(permissions, namespaceScope)
}

func currentRoleSnapshot(role *iamentity.Role) *iamentity.Role {
	if role == nil {
		return nil
	}
	snapshot := *role
	return &snapshot
}

func (s *RoleService) resolveTenantScope(ctx context.Context, tenantID string) (*iamentity.Scope, error) {
	if s.scopeAuthorizer == nil {
		return nil, nil
	}
	return s.scopeAuthorizer.ResolveTenantScope(ctx, tenantID)
}

func (s *RoleService) resolveRoleNamespaceScope(ctx context.Context, role *iamentity.Role) (*iamentity.Scope, error) {
	if role == nil {
		return nil, errors.NewCode(errors.InvalidInput, "role is required")
	}
	if s.scopeAuthorizer == nil {
		return nil, nil
	}
	if role.NamespaceScopeID > 0 {
		scope, err := s.scopeAuthorizer.Scope(ctx, role.NamespaceScopeID)
		if err == nil {
			return scope, nil
		}
		if !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}
	return s.resolveTenantScope(ctx, role.TenantID)
}

func (s *RoleService) initializeBuiltinRoles(ctx context.Context, tenantID string, namespaceScope *iamentity.Scope) error {
	if namespaceScope == nil {
		return s.roleRepo.InitializeSystemRoles(ctx)
	}

	var builtinRoles []*iamentity.Role
	switch namespaceScope.Type {
	case iamentity.ScopeTypePlatform:
		builtinRoles = []*iamentity.Role{
			iamentity.SystemAdminRole,
			iamentity.UserRole,
		}
	default:
		builtinRoles = []*iamentity.Role{
			iamentity.TenantAdminRole,
			iamentity.UserRole,
		}
	}

	for _, builtin := range builtinRoles {
		existing, err := s.roleRepo.FindByName(ctx, builtin.Name)
		if err != nil && !errors.Is(err, errors.NotFound) {
			return err
		}
		if existing != nil {
			continue
		}
		clone := *builtin
		clone.TenantID = tenantID
		clone.NamespaceScopeID = namespaceScope.ID
		clone.Code = builtin.Name
		if err := s.roleRepo.Create(ctx, &clone); err != nil {
			return errors.Wrap(err, errors.Database, "初始化内置角色失败: "+builtin.Name)
		}
	}
	return nil
}

// 发布用户角色相关事件（内部辅助方法）

// publishUserRoleAssignedEvent 处理publish用户角色Assigned事件。
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

	evt, err := eventing.NewEvent(s.eventIDGenerator, userID, "user", payload.GetType(), 1, payload)
	if err != nil {
		s.logger.Warn(ctx, "[RoleService] 生成 UserRoleAssigned 事件失败", logging.Error(err), logging.Int64("user_id", userID))
		return
	}
	if err := s.eventBus.PublishEvent(ctx, evt); err != nil {
		s.logger.Warn(ctx, "[RoleService] 发布 UserRoleAssigned 事件失败",
			logging.Error(err),
			logging.Int64("user_id", userID),
			logging.Int64("role_id", role.GetID()),
			logging.String("role_code", role.Code),
		)
	}
}

// publishUserRoleRemovedEvent 处理publish用户角色Removed事件。
func (s *RoleService) publishUserRoleRemovedEvent(ctx context.Context, userID, roleID int64) {
	if s.eventBus == nil {
		return
	}

	payload := &iamevent.UserRoleRemoved{
		UserID:    userID,
		RoleID:    roleID,
		RemovedAt: time.Now(),
	}

	evt, err := eventing.NewEvent(s.eventIDGenerator, userID, "user", payload.GetType(), 1, payload)
	if err != nil {
		s.logger.Warn(ctx, "[RoleService] 生成 UserRoleRemoved 事件失败", logging.Error(err), logging.Int64("user_id", userID))
		return
	}
	if err := s.eventBus.PublishEvent(ctx, evt); err != nil {
		s.logger.Warn(ctx, "[RoleService] 发布 UserRoleRemoved 事件失败",
			logging.Error(err),
			logging.Int64("user_id", userID),
			logging.Int64("role_id", roleID),
		)
	}
}
