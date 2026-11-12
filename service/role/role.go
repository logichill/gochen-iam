package role

import (
	"context"

	stdErrors "errors"
	"time"

	iamauth "gochen-iam/auth"

	iamentity "gochen-iam/entity"

	iamevent "gochen-iam/event"

	grouprepo "gochen-iam/repo/group"

	rolerepo "gochen-iam/repo/role"

	userrepo "gochen-iam/repo/user"

	svc "gochen-iam/service"

	appcrud "gochen/app/crud"
	dbquery "gochen/app/query"
	"gochen/auth/scoped"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/eventing"
	"gochen/eventing/bus"
	"gochen/gen"
	"gochen/observe/logging"
)

var errBulkAssignRoleRollback = stdErrors.New("rollback bulk assign role")

// RoleService 角色服务
type RoleService struct {
	roleRepo                             *rolerepo.RoleRepo
	userRepo                             *userrepo.UserRepo
	groupRepo                            *grouprepo.GroupRepo
	scopeAuthorizer                      *svc.ScopeAuthorizer
	authorizer                           *svc.IAMAccess
	eventBus                             bus.IEventBus
	eventIDGenerator                     gen.IGenerator[string]
	logger                               logging.ILogger
	governance                           *Governance
	statisticsCommands                   map[string]*roleStatisticsCommand
	writeCommands                        map[string]*roleWriteCommand
	systemCommands                       map[string]*roleSystemCommand
	crudApplication, httpCRUDApplication *roleCRUDApplication
	directoryCommands                    map[string]*roleDirectoryCommand
	groupCommands                        map[string]*roleGroupCommand
	permissionCommand                    *rolePermissionCommand
	permissionsCommand                   *rolePermissionsCommand
	userCommands                         map[string]*roleUserCommand
	initializeCommand                    *roleInitializeCommand
	usersCommand                         *roleUsersCommand
	groupsCommand                        *roleGroupsCommand
}

// NewRoleService 创建角色服务实例
func NewRoleService(
	roleRepo *rolerepo.RoleRepo,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAccess,
	eventBus bus.IEventBus,
	eventIDGenerator gen.IGenerator[string],
	logger logging.ILogger,
) (*RoleService, error) {

	s := &RoleService{
		roleRepo:         roleRepo,
		userRepo:         userRepo,
		groupRepo:        groupRepo,
		scopeAuthorizer:  scopeAuthorizer,
		authorizer:       authorizer,
		eventBus:         eventBus,
		eventIDGenerator: eventIDGenerator,
		logger:           logging.ComponentLogger("iam.service.role", logger),
		governance:       NewGovernance(roleRepo, userRepo, scopeAuthorizer),
	}
	if roleRepo == nil || roleRepo.Repo == nil || userRepo == nil || userRepo.Repo == nil || groupRepo == nil || groupRepo.Repo == nil || authorizer == nil {
		return nil, errors.NewCode(errors.InvalidInput, "role service requires its actual role/user/group repositories and IAM declarations")
	}
	// Commands retain their construction-time providers for their entire lifetime.
	bound := *s
	if err := bound.compileStatisticsCommands(); err != nil {
		return nil, err
	}
	s.statisticsCommands = bound.statisticsCommands
	if err := bound.compileWriteCommands(); err != nil {
		return nil, err
	}
	s.writeCommands = bound.writeCommands
	if err := bound.compileSystemCommands(); err != nil {
		return nil, err
	}
	s.systemCommands = bound.systemCommands
	if err := bound.compileCRUDApplications(); err != nil {
		return nil, err
	}
	s.crudApplication, s.httpCRUDApplication = bound.crudApplication, bound.httpCRUDApplication
	if err := bound.compileDirectoryCommands(); err != nil {
		return nil, err
	}
	s.directoryCommands = bound.directoryCommands
	if err := bound.compileGroupCommands(); err != nil {
		return nil, err
	}
	s.groupCommands = bound.groupCommands
	if err := bound.compilePermissionCommand(); err != nil {
		return nil, err
	}
	s.permissionCommand = bound.permissionCommand
	if err := bound.compileUserCommands(); err != nil {
		return nil, err
	}
	s.userCommands = bound.userCommands
	if err := bound.compilePermissionsCommand(); err != nil {
		return nil, err
	}
	s.permissionsCommand = bound.permissionsCommand
	if err := bound.compileInitializeCommand(); err != nil {
		return nil, err
	}
	s.initializeCommand = bound.initializeCommand
	if err := bound.compileRoleUsersCommand(); err != nil {
		return nil, err
	}
	s.usersCommand = bound.usersCommand
	if err := bound.compileRoleGroupsCommand(); err != nil {
		return nil, err
	}
	s.groupsCommand = bound.groupsCommand
	return s, nil
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
	if req == nil {
		return nil, errors.NewCode(errors.InvalidInput, "role request is required")
	}
	if err := s.validateCreateRoleRequest(req); err != nil {
		return nil, err
	}
	tenantID, err := svc.NormalizeTenantID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	ctx, err = svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	item := &iamentity.Role{TenantID: tenantID, OwnerID: svc.TenantOwnerID(tenantID), Name: req.Name, Description: req.Description, Permissions: iamentity.PermissionArray(req.Permissions)}
	err = s.crudApplication.Create(ctx, item)
	if err != nil {
		return nil, err
	}
	return item, nil
}

// UpdateRole 更新角色。
func (s *RoleService) UpdateRole(ctx context.Context, roleID int64, req *svc.UpdateRoleRequest) (*iamentity.Role, error) {
	if req == nil {
		return nil, errors.NewCode(errors.InvalidInput, "role update is required")
	}
	return s.crudApplication.Execute(ctx, "update", roleID, func(_ context.Context, item *iamentity.Role) error {
		if req.Name != "" {
			item.Name = req.Name
		}
		if req.Description != "" {
			item.Description = req.Description
		}
		if len(req.Permissions) > 0 {
			item.SetPermissions(req.Permissions)
		}
		return nil
	})
}

// DeleteRole 删除角色。
func (s *RoleService) DeleteRole(ctx context.Context, roleID int64) error {
	return s.crudApplication.Delete(ctx, roleID)
}

// AssignRoleToUser 将角色分配给用户
func (s *RoleService) AssignRoleToUser(ctx context.Context, roleID, userID int64) error {
	_, err := s.userCommands["assign_user"].Execute(ctx, roleUserInput{roleID, userID})
	return err
}

// RemoveRoleFromUser 从用户移除角色
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, roleID, userID int64) error {
	_, err := s.userCommands["remove_user"].Execute(ctx, roleUserInput{roleID, userID})
	return err
}

// AssignRoleToGroup 将角色分配给组织作为默认角色
func (s *RoleService) AssignRoleToGroup(ctx context.Context, roleID, groupID int64) error {
	_, err := s.groupCommands["assign_group"].Execute(ctx, roleGroupInput{roleID, groupID})
	return err
}

// RemoveRoleFromGroup 从组织移除默认角色
func (s *RoleService) RemoveRoleFromGroup(ctx context.Context, roleID, groupID int64) error {
	_, err := s.groupCommands["remove_group"].Execute(ctx, roleGroupInput{roleID, groupID})
	return err
}

// AddPermission 为角色添加权限
func (s *RoleService) AddPermission(ctx context.Context, roleID int64, permission string) error {
	_, err := s.crudApplication.Execute(ctx, "update", roleID, func(_ context.Context, item *iamentity.Role) error { item.AddPermission(permission); return nil })
	return err
}

// RemovePermission 从角色移除权限
func (s *RoleService) RemovePermission(ctx context.Context, roleID int64, permission string) error {
	return s.executeWrite(ctx, "remove_permission", RoleWriteInput{ID: roleID, Permission: permission})
}

// ActivateRole 激活角色
func (s *RoleService) ActivateRole(ctx context.Context, roleID int64) error {
	return s.executeWrite(ctx, "activate", RoleWriteInput{ID: roleID})
}

// DeactivateRole 停用角色
func (s *RoleService) DeactivateRole(ctx context.Context, roleID int64) error {
	return s.executeWrite(ctx, "deactivate", RoleWriteInput{ID: roleID})
}

// CloneRole 克隆角色
func (s *RoleService) CloneRole(ctx context.Context, roleID int64, newName string) (*iamentity.Role, error) {
	command, err := s.crudApplication.cloneCommand()
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, roleCRUDInput{IDs: []int64{roleID}, Name: newName})
}

// RoleUsers 获取拥有指定角色的用户
func (s *RoleService) RoleUsers(ctx context.Context, roleID int64) ([]*iamentity.User, error) {
	return s.usersCommand.Execute(ctx, roleID)
}

// RoleGroups 获取使用指定角色作为默认角色的组织
func (s *RoleService) RoleGroups(ctx context.Context, roleID int64) ([]*iamentity.Group, error) {
	return s.groupsCommand.Execute(ctx, roleID)
}

// CheckPermission 检查权限
func (s *RoleService) CheckPermission(ctx context.Context, req *svc.PermissionCheckRequest) (*svc.PermissionCheckResponse, error) {
	if req == nil {
		return nil, errors.NewCode(errors.InvalidInput, "permission check is required")
	}
	return s.permissionCommand.Execute(ctx, *req)
}

// SearchRoles 搜索角色
func (s *RoleService) SearchRoles(ctx context.Context, keyword string, limit int) ([]*iamentity.Role, error) {
	result, err := s.directoryCommands["search"].Execute(ctx, roleDirectoryInput{Keyword: keyword, Query: dbquery.QueryOptions{Limit: limit}})
	return result.Items, err
}

// ActiveRoles 获取激活状态的角色
func (s *RoleService) ActiveRoles(ctx context.Context) ([]*iamentity.Role, error) {
	result, err := s.directoryCommands["active"].Execute(ctx, roleDirectoryInput{Query: dbquery.QueryOptions{Limit: 1000}})
	return result.Items, err
}

// SystemRoles 获取系统角色
func (s *RoleService) SystemRoles(ctx context.Context) ([]*iamentity.Role, error) {
	return s.systemCommands["system_roles"].Execute(ctx, struct{}{})
}

// InitializeSystemRoles 初始化系统角色（租户维度）
func (s *RoleService) InitializeSystemRoles(ctx context.Context, tenantID string) error {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	ctx, err = svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = s.initializeCommand.Execute(ctx, struct{}{})
	return err
}

// RoleStatistics 返回角色统计信息。
func (s *RoleService) RoleStatistics(ctx context.Context) (map[string]interface{}, error) {
	return s.statisticsCommands["statistics"].Execute(ctx, struct{}{})
}

// roleReadSpec 使用 IAM 的统一事实源解析自定义读取的数据范围。
func roleReadSpec(ctx context.Context) (spec.Spec, error) {
	scope, err := iamauth.DefaultDataScopeResolver.ResolveDataScope(ctx)
	if err != nil {
		return spec.Spec{}, err
	}
	boundCtx, err := scoped.WithDataScope(ctx, scope)
	if err != nil {
		return spec.Spec{}, err
	}
	return svc.DataScopeSpec(boundCtx), nil
}

// BulkAssignRole 批量分配角色（事务包裹）
func (s *RoleService) BulkAssignRole(ctx context.Context, req *svc.RoleAssignRequest) (*svc.BulkOperationResponse, error) {
	response := &svc.BulkOperationResponse{}
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
			return errBulkAssignRoleRollback
		}
		return nil
	})
	if err != nil && !stdErrors.Is(err, errBulkAssignRoleRollback) {
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
//
//nolint:unused // 仅供包内测试调用，保留对 --tests=false 检查的兼容。
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

func (s *RoleService) initializeBuiltinRoles(ctx context.Context, tenantID string, namespaceScope *iamentity.Scope, conditions ...spec.Spec) error {
	guard := spec.All()
	if len(conditions) > 0 {
		guard = spec.And(conditions...)
	}
	if namespaceScope == nil {
		return s.roleRepo.InitializeSystemRoles(ctx, guard)
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
		if err := s.roleRepo.Create(ctx, &clone, guard); err != nil {
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
