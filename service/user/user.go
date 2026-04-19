package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"

	grouprepo "gochen-iam/repo/group"

	rolerepo "gochen-iam/repo/role"

	userrepo "gochen-iam/repo/user"

	svc "gochen-iam/service"
	"gochen/auth"
	"gochen/errors"
	"gochen/logging"
)

// UserService 用户服务
type UserService struct {
	userRepo        *userrepo.UserRepo
	groupRepo       *grouprepo.GroupRepo
	roleRepo        *rolerepo.RoleRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      auth.IAuthorizer
	logger          logging.ILogger
}

// NewUserService 创建用户服务实例
func NewUserService(
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *auth.Authorizer,
) *UserService {
	return &UserService{
		userRepo:        userRepo,
		groupRepo:       groupRepo,
		roleRepo:        roleRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
		logger:          logging.ComponentLogger("iam.service.user"),
	}
}

// Register 用户注册
//
// tenantID 从上下文中提取（由 middleware 注入），而非从请求体获取，
// 以防止客户端伪造租户 ID 导致跨租户写入。
func (s *UserService) Register(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error) {
	// 1. 验证请求数据
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// 2. 解析租户：多租户模式要求上下文 tenant；固定租户模式会自动回落到配置的默认 tenant。
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
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

	// 3. 检查用户名是否已存在
	existingUser, err := s.userRepo.FindByUsername(tenantCtx, req.Username)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return nil, errors.Wrap(err, errors.Database, "检查用户名失败")
	}
	if existingUser != nil {
		return nil, errors.NewCode(errors.Validation, "用户名已存在")
	}

	// 3. 检查邮箱是否已存在
	existingUser, err = s.userRepo.FindByEmail(tenantCtx, req.Email)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return nil, errors.Wrap(err, errors.Database, "检查邮箱失败")
	}
	if existingUser != nil {
		return nil, errors.NewCode(errors.Validation, "邮箱已存在")
	}

	// 4. 创建用户实体
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal, "密码加密失败")
	}

	user := &iamentity.User{
		TenantID:       tenantID,
		HomeTenantID:   tenantID,
		HomeScopeID:    managedScopeID,
		ManagedScopeID: managedScopeID,
		OwnerID:        svc.TenantOwnerID(tenantID),
		Username:       req.Username,
		Email:          req.Email,
		Password:       hashedPassword,
		Status:         svc.UserStatusActive,
	}
	user.SetUpdatedAt(time.Now())

	// 5. 保存用户
	guard, err := svc.NewCreateWriteConstraint(tenantCtx, svc.UserResourceKind, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.userRepo.CreateWithConstraint(tenantCtx, user, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "保存用户失败")
	}

	// 6. 分配默认角色
	if err := s.assignDefaultRole(tenantCtx, user.TenantID, user.GetID()); err != nil {
		// 记录错误但不影响注册流程
		s.logger.Warn(ctx, "[UserService] 分配默认角色失败",
			logging.Error(err),
			logging.Int64("user_id", user.GetID()),
			logging.String("username", user.Username),
		)
	}

	return user, nil
}

// Authenticate 用户认证第一阶段：校验用户名/密码，返回可进入的 scope 集合。
func (s *UserService) Authenticate(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error) {
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}
	if req.Username == "" || req.Password == "" {
		return nil, errors.NewCode(errors.Validation, "用户名和密码不能为空")
	}
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByUsername(tenantCtx, req.Username)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户名或密码错误")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}
	if !s.verifyPassword(req.Password, user.Password) {
		return nil, errors.NewCode(errors.Validation, "用户名或密码错误")
	}
	if !user.IsActive() {
		return nil, errors.NewCode(errors.Forbidden, "用户账户已被禁用")
	}

	user.UpdateLastLogin()
	if err := s.updateUserWithGuard(tenantCtx, user); err != nil {
		s.logger.Warn(ctx, "[UserService] 更新最后登录时间失败",
			logging.Error(err),
			logging.Int64("user_id", user.GetID()),
			logging.String("username", user.Username),
		)
	}

	availableScopes, bindingVersion, err := s.resolveAvailableScopes(tenantCtx, user)
	if err != nil {
		return nil, err
	}
	if len(availableScopes) == 0 {
		return nil, errors.NewCode(errors.Forbidden, "当前用户没有可激活的授权域")
	}

	return &svc.AuthenticateResult{
		UserID:          user.GetID(),
		Username:        user.Username,
		Email:           user.Email,
		BindingVersion:  bindingVersion,
		AvailableScopes: availableScopes,
	}, nil
}

// ActivateScope 用户认证第二阶段：显式选择 active scope，返回可签发 access token 的最小快照。
func (s *UserService) ActivateScope(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
	if activeScopeID <= 0 {
		return nil, errors.NewCode(errors.Validation, "active scope is required")
	}
	user, _, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errors.NewCode(errors.Forbidden, "用户账户已被禁用")
	}
	authCtx, err := svc.BindTenantContext(ctx, user.TenantID)
	if err != nil {
		return nil, err
	}
	return s.buildScopeSession(authCtx, user, activeScopeID)
}

// AuthSnapshot 返回当前 active scope 下的最新权限快照，用于 refresh token。
func (s *UserService) AuthSnapshot(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
	if activeScopeID <= 0 {
		return nil, errors.NewCode(errors.Validation, "active scope is required")
	}
	user, _, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errors.NewCode(errors.Forbidden, "用户账户已被禁用")
	}
	authCtx, err := svc.BindTenantContext(ctx, user.TenantID)
	if err != nil {
		return nil, err
	}
	return s.buildScopeSession(authCtx, user, activeScopeID)
}

// resolveEffectiveRolesAndPermissions 解析当前生效的角色与权限。
//
// 合并来源：
// 1. 用户直接分配的角色（user_roles）
// 2. 用户所属 Group 的默认角色（group_roles）
func (s *UserService) resolveEffectiveRolesAndPermissions(ctx context.Context, userID int64) ([]string, []string, error) {
	// 1. 用户直接分配的角色
	directRoles, err := s.roleRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	// 2. 用户所属 Group 的默认角色
	groups, err := s.groupRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	var groupRoles []*iamentity.Role
	for _, group := range groups {
		if group == nil {
			continue
		}
		roles, err := s.roleRepo.FindByGroupID(ctx, group.GetID())
		if err != nil {
			return nil, nil, err
		}
		groupRoles = append(groupRoles, roles...)
	}

	// 3. 合并去重
	roleNames := make([]string, 0, len(directRoles)+len(groupRoles))
	roleSet := make(map[string]struct{}, len(directRoles)+len(groupRoles))

	permissions := make([]string, 0)
	permissionSet := make(map[string]struct{})

	mergeRole := func(role *iamentity.Role) {
		if role == nil || role.Status != svc.RoleStatusActive {
			return
		}
		name := strings.TrimSpace(role.Name)
		if name != "" {
			if _, exists := roleSet[name]; !exists {
				roleSet[name] = struct{}{}
				roleNames = append(roleNames, name)
			}
		}
		for _, permission := range role.Permissions {
			permission = strings.TrimSpace(permission)
			if permission == "" {
				continue
			}
			if _, exists := permissionSet[permission]; !exists {
				permissionSet[permission] = struct{}{}
				permissions = append(permissions, permission)
			}
		}
	}

	for i := range directRoles {
		mergeRole(directRoles[i])
	}
	for i := range groupRoles {
		mergeRole(groupRoles[i])
	}

	// 固定输出顺序，避免测试与 token 声明受数据库返回顺序影响。
	sort.Strings(roleNames)
	sort.Strings(permissions)

	return roleNames, permissions, nil
}

type authScopeAggregate struct {
	ScopeID       int64
	BindingIDs    []int64
	RoleNames     []string
	Permissions   []string
	roleSet       map[string]struct{}
	permissionSet map[string]struct{}
	bindingIDSet  map[int64]struct{}
}

func (s *UserService) buildScopeSession(
	ctx context.Context,
	user *iamentity.User,
	activeScopeID int64,
) (*svc.ActiveScopeSession, error) {
	if user == nil {
		return nil, errors.NewCode(errors.InvalidInput, "user is required")
	}
	availableScopes, bindingVersion, err := s.resolveAvailableScopes(ctx, user)
	if err != nil {
		return nil, err
	}
	for _, scope := range availableScopes {
		if scope.ScopeID != activeScopeID {
			continue
		}
		return &svc.ActiveScopeSession{
			UserID:         user.GetID(),
			Username:       user.Username,
			Email:          user.Email,
			ActiveScopeID:  activeScopeID,
			BindingVersion: bindingVersion,
			RoleNames:      append([]string(nil), scope.RoleNames...),
			Permissions:    append([]string(nil), scope.Permissions...),
		}, nil
	}
	return nil, errors.NewCode(errors.Forbidden, "当前用户不能激活目标授权域")
}

func (s *UserService) resolveAvailableScopes(ctx context.Context, user *iamentity.User) ([]svc.AuthScopeOption, string, error) {
	if user == nil {
		return nil, "", errors.NewCode(errors.InvalidInput, "user is required")
	}

	aggregates := map[int64]*authScopeAggregate{}
	addRole := func(scopeID, bindingID int64, role *iamentity.Role) {
		if scopeID <= 0 || role == nil || !role.IsActive() {
			return
		}
		scope := aggregates[scopeID]
		if scope == nil {
			scope = &authScopeAggregate{
				ScopeID:       scopeID,
				roleSet:       map[string]struct{}{},
				permissionSet: map[string]struct{}{},
				bindingIDSet:  map[int64]struct{}{},
			}
			aggregates[scopeID] = scope
		}
		if bindingID > 0 {
			if _, ok := scope.bindingIDSet[bindingID]; !ok {
				scope.bindingIDSet[bindingID] = struct{}{}
				scope.BindingIDs = append(scope.BindingIDs, bindingID)
			}
		}
		if role.Name != "" {
			if _, ok := scope.roleSet[role.Name]; !ok {
				scope.roleSet[role.Name] = struct{}{}
				scope.RoleNames = append(scope.RoleNames, role.Name)
			}
		}
		for _, permission := range role.Permissions {
			permission = strings.TrimSpace(permission)
			if permission == "" {
				continue
			}
			if _, ok := scope.permissionSet[permission]; ok {
				continue
			}
			scope.permissionSet[permission] = struct{}{}
			scope.Permissions = append(scope.Permissions, permission)
		}
	}

	bindings, err := s.userRepo.ListRoleBindings(ctx, user.GetID())
	if err != nil {
		return nil, "", err
	}
	for _, binding := range bindings {
		role, err := s.roleRepo.Get(ctx, binding.RoleID)
		if err != nil {
			if errors.Is(err, errors.NotFound) {
				continue
			}
			return nil, "", err
		}
		addRole(binding.GrantScopeID, binding.BindingID, role)
	}

	groups, err := s.groupRepo.FindByUserID(ctx, user.GetID())
	if err != nil {
		return nil, "", err
	}
	for _, group := range groups {
		if group == nil {
			continue
		}
		roles, err := s.roleRepo.FindByGroupID(ctx, group.GetID())
		if err != nil {
			return nil, "", err
		}
		for _, role := range roles {
			addRole(role.NamespaceScopeID, 0, role)
		}
	}

	if len(aggregates) == 0 && user.HomeScopeID > 0 {
		aggregates[user.HomeScopeID] = &authScopeAggregate{
			ScopeID:       user.HomeScopeID,
			roleSet:       map[string]struct{}{},
			permissionSet: map[string]struct{}{},
			bindingIDSet:  map[int64]struct{}{},
		}
	}

	scopeIDs := make([]int64, 0, len(aggregates))
	for scopeID := range aggregates {
		scopeIDs = append(scopeIDs, scopeID)
	}
	sort.Slice(scopeIDs, func(i, j int) bool { return scopeIDs[i] < scopeIDs[j] })

	options := make([]svc.AuthScopeOption, 0, len(scopeIDs))
	for _, scopeID := range scopeIDs {
		aggregate := aggregates[scopeID]
		if aggregate == nil {
			continue
		}
		sort.Slice(aggregate.BindingIDs, func(i, j int) bool { return aggregate.BindingIDs[i] < aggregate.BindingIDs[j] })
		sort.Strings(aggregate.RoleNames)
		sort.Strings(aggregate.Permissions)

		option := svc.AuthScopeOption{
			ScopeID:     scopeID,
			BindingIDs:  append([]int64(nil), aggregate.BindingIDs...),
			RoleNames:   append([]string(nil), aggregate.RoleNames...),
			Permissions: append([]string(nil), aggregate.Permissions...),
		}
		if s.scopeAuthorizer != nil {
			scope, err := s.scopeAuthorizer.Scope(ctx, scopeID)
			if err != nil {
				if errors.Is(err, errors.NotFound) {
					continue
				}
				return nil, "", err
			}
			option.ScopeKey = scope.Key
			option.ScopeKind = scope.Type
		}
		options = append(options, option)
	}
	if len(options) == 0 {
		return nil, "", nil
	}
	return options, computeBindingVersion(options), nil
}

func computeBindingVersion(options []svc.AuthScopeOption) string {
	hasher := sha256.New()
	for _, option := range options {
		_, _ = hasher.Write([]byte(fmt.Sprintf("%d|%s|%s|", option.ScopeID, option.ScopeKey, option.ScopeKind)))
		for _, bindingID := range option.BindingIDs {
			_, _ = hasher.Write([]byte(fmt.Sprintf("b:%d|", bindingID)))
		}
		for _, roleName := range option.RoleNames {
			_, _ = hasher.Write([]byte("r:" + roleName + "|"))
		}
		for _, permission := range option.Permissions {
			_, _ = hasher.Write([]byte("p:" + permission + "|"))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(ctx context.Context, userID int64, req *svc.ChangePasswordRequest) error {
	// 1. 获取用户
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	if _, err := svc.PreflightTenant(ctx, s.scopeAuthorizer, user.TenantID, ""); err != nil {
		return err
	}

	// 2. 验证旧密码
	if !s.verifyPassword(req.OldPassword, user.Password) {
		return errors.NewCode(errors.Validation, "原密码错误")
	}

	// 3. 验证新密码
	if len(req.NewPassword) < svc.MinPasswordLength {
		return errors.NewCode(errors.Validation, "新密码长度不能少于6个字符")
	}

	// 4. 更新密码
	hashedPassword, err := s.hashPassword(req.NewPassword)
	if err != nil {
		return errors.Wrap(err, errors.Internal, "密码加密失败")
	}
	user.Password = hashedPassword
	user.SetUpdatedAt(time.Now())

	return s.updateUserWithGuard(tenantCtx, user)
}

// UpdateProfile 更新用户资料
func (s *UserService) UpdateProfile(ctx context.Context, userID int64, req *svc.UpdateUserRequest) (*iamentity.User, error) {
	// 1. 获取用户
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.PreflightTenant(ctx, s.scopeAuthorizer, user.TenantID, ""); err != nil {
		return nil, err
	}

	// 2. 更新字段
	if req.Email != "" && req.Email != user.Email {
		// 检查邮箱是否已被使用
		existingUser, err := s.userRepo.FindByEmail(tenantCtx, req.Email)
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, errors.Wrap(err, errors.Database, "检查邮箱失败")
		}
		if existingUser != nil && existingUser.GetID() != userID {
			return nil, errors.NewCode(errors.Validation, "邮箱已被使用")
		}
		user.Email = req.Email
	}

	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}

	user.SetUpdatedAt(time.Now())

	// 3. 保存更新
	if err := s.updateUserWithGuard(tenantCtx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// ActivateUser 激活用户
func (s *UserService) ActivateUser(ctx context.Context, userID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	if err := s.updateUserWithAuthorization(tenantCtx, svc.UserPermissionSet.Code(iammw.ActionWrite), user, user.Activate); err != nil {
		return err
	}
	return nil
}

// DeactivateUser 停用用户
func (s *UserService) DeactivateUser(ctx context.Context, userID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	if err := s.updateUserWithAuthorization(tenantCtx, svc.UserPermissionSet.Code(iammw.ActionWrite), user, user.Deactivate); err != nil {
		return err
	}
	return nil
}

// LockUser 锁定用户
func (s *UserService) LockUser(ctx context.Context, userID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	if err := s.updateUserWithAuthorization(tenantCtx, svc.UserPermissionSet.Code(iammw.ActionWrite), user, user.Lock); err != nil {
		return err
	}
	return nil
}

// UnlockUser 解锁用户
func (s *UserService) UnlockUser(ctx context.Context, userID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	if err := s.updateUserWithAuthorization(tenantCtx, svc.UserPermissionSet.Code(iammw.ActionWrite), user, user.Unlock); err != nil {
		return err
	}
	return nil
}

// AssignRole 为用户分配角色。
func (s *UserService) AssignRole(ctx context.Context, userID, roleID int64) error {
	return s.AssignRoleBinding(ctx, userID, roleID, nil)
}

// AssignRoleBinding 在指定 grant scope 下为用户分配角色。
func (s *UserService) AssignRoleBinding(ctx context.Context, userID, roleID int64, grantScopeID *int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	role, roleVisible, err := s.resolveRoleForScope(tenantCtx, user.TenantID, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return errors.NewCode(errors.NotFound, "角色不存在")
	}
	if !roleVisible {
		return errors.NewCode(errors.Forbidden, "当前 active scope 无法访问该角色，请切换到角色所属授权域后重试")
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.UserPermissionSet.Code(iammw.ActionWrite), user, role)
	if err != nil {
		return err
	}
	if role.Status != svc.RoleStatusActive {
		return errors.NewCode(errors.Validation, "只能分配激活状态的角色")
	}

	targetScopeID := role.NamespaceScopeID
	if currentScopeID := svc.ManagedScopeIDFromContext(tenantCtx); currentScopeID > 0 {
		targetScopeID = currentScopeID
	}
	if grantScopeID != nil && *grantScopeID > 0 {
		targetScopeID = *grantScopeID
	}
	if err := s.ensureGrantScopeAllowed(tenantCtx, role, targetScopeID); err != nil {
		return err
	}
	boundCtx, err := svc.BindManagedScopeContext(tenantCtx, targetScopeID)
	if err != nil {
		return err
	}
	return s.userRepo.AssignRoleWithConstraint(boundCtx, userID, roleID, guard)
}

// RemoveRole 移除用户角色。
func (s *UserService) RemoveRole(ctx context.Context, userID, roleID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	role, err := s.roleRepo.Get(tenantCtx, roleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.UserPermissionSet.Code(iammw.ActionWrite), user, role)
	if err != nil {
		return err
	}
	return s.userRepo.RemoveRoleWithConstraint(tenantCtx, userID, roleID, guard)
}

// RemoveRoleBinding 按 binding id 移除用户角色绑定。
func (s *UserService) RemoveRoleBinding(ctx context.Context, userID, bindingID int64) error {
	binding, err := s.userRepo.GetRoleBinding(ctx, bindingID)
	if err != nil {
		return err
	}
	if binding.UserID != userID {
		return errors.NewCode(errors.Forbidden, "角色绑定与目标用户不匹配")
	}
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	role, err := s.roleRepo.Get(tenantCtx, binding.RoleID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.UserPermissionSet.Code(iammw.ActionWrite), user, role)
	if err != nil {
		return err
	}
	if err := s.ensureGrantScopeVisible(tenantCtx, binding.GrantScopeID); err != nil {
		return err
	}
	_ = guard
	return s.userRepo.RemoveRoleBinding(tenantCtx, bindingID)
}

// AssignToGroup 将用户分配到组织
func (s *UserService) AssignToGroup(ctx context.Context, userID, groupID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(tenantCtx, groupID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.UserPermissionSet.Code(iammw.ActionWrite), user, group)
	if err != nil {
		return err
	}
	return s.userRepo.AssignToGroupWithConstraint(tenantCtx, userID, groupID, guard)
}

// RemoveFromGroup 从组织中移除用户
func (s *UserService) RemoveFromGroup(ctx context.Context, userID, groupID int64) error {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return err
	}
	group, err := s.groupRepo.Get(tenantCtx, groupID)
	if err != nil {
		return err
	}
	guard, err := svc.AuthorizeWriteConstraint(tenantCtx, s.authorizer, svc.UserPermissionSet.Code(iammw.ActionWrite), user, group)
	if err != nil {
		return err
	}
	return s.userRepo.RemoveFromGroupWithConstraint(tenantCtx, userID, groupID, guard)
}

// UserPermissions 获取用户权限。
//
// 语义：
// - 用户不存在：返回 NotFound；
// - 用户非 active：返回错误（fail-close，避免禁用账号仍可参与鉴权/授权决策）。
func (s *UserService) UserPermissions(ctx context.Context, userID int64) ([]string, error) {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), user.TenantID); err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errors.NewCode(errors.Forbidden, "用户账户已被禁用")
	}

	_, permissions, err := s.resolveEffectiveRolesAndPermissions(tenantCtx, userID)
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

// CheckPermission 检查用户权限
func (s *UserService) CheckPermission(ctx context.Context, userID int64, permission string) (bool, error) {
	permissions, err := s.UserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}
	return (auth.Principal{Permissions: permissions}).AllowsPermission(permission), nil
}

func (s *UserService) ensureGrantScopeAllowed(ctx context.Context, role *iamentity.Role, grantScopeID int64) error {
	if grantScopeID <= 0 {
		return errors.NewCode(errors.InvalidInput, "grant scope is required")
	}
	if s.scopeAuthorizer == nil {
		return nil
	}
	if _, err := s.scopeAuthorizer.Scope(ctx, grantScopeID); err != nil {
		return err
	}
	if activeScopeID := svc.ManagedScopeIDFromContext(ctx); activeScopeID > 0 {
		allowed, err := s.scopeAuthorizer.ScopeCovers(ctx, activeScopeID, grantScopeID)
		if err != nil {
			return err
		}
		if !allowed && activeScopeID != grantScopeID {
			return errors.NewCode(errors.Forbidden, "当前 active scope 不能授予目标授权域")
		}
	}
	if role != nil && role.NamespaceScopeID > 0 && role.NamespaceScopeID != grantScopeID {
		allowed, err := s.scopeAuthorizer.ScopeCovers(ctx, role.NamespaceScopeID, grantScopeID)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.NewCode(errors.Forbidden, "目标授权域不在角色 namespace scope 覆盖范围内")
		}
	}
	return nil
}

func (s *UserService) ensureGrantScopeVisible(ctx context.Context, grantScopeID int64) error {
	if grantScopeID <= 0 || s.scopeAuthorizer == nil {
		return nil
	}
	if activeScopeID := svc.ManagedScopeIDFromContext(ctx); activeScopeID > 0 && activeScopeID != grantScopeID {
		allowed, err := s.scopeAuthorizer.ScopeCovers(ctx, activeScopeID, grantScopeID)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.NewCode(errors.Forbidden, "当前 active scope 无法查看目标授权域绑定")
		}
	}
	return nil
}

// SearchUsers 搜索用户
func (s *UserService) SearchUsers(ctx context.Context, keyword string, limit int) ([]*iamentity.User, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.userRepo.SearchUsers(tenantCtx, keyword, limit)
}

// UsersByStatus 根据状态获取用户
func (s *UserService) UsersByStatus(ctx context.Context, status string) ([]*iamentity.User, error) {
	tenantID, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), tenantID); err != nil {
		return nil, err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.userRepo.FindByStatus(tenantCtx, status)
}

// UserRoles 获取用户角色
func (s *UserService) UserRoles(ctx context.Context, userID int64) ([]*iamentity.Role, error) {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), user.TenantID); err != nil {
		return nil, err
	}
	return s.roleRepo.FindByUserID(tenantCtx, userID)
}

// UserRoleBindings 获取用户的直接角色绑定。
func (s *UserService) UserRoleBindings(ctx context.Context, userID int64) ([]*svc.UserRoleBindingDetail, error) {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), user.TenantID); err != nil {
		return nil, err
	}
	bindings, err := s.userRepo.ListRoleBindings(tenantCtx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*svc.UserRoleBindingDetail, 0, len(bindings))
	for _, binding := range bindings {
		if err := s.ensureGrantScopeVisible(tenantCtx, binding.GrantScopeID); err != nil {
			if errors.Is(err, errors.Forbidden) {
				continue
			}
			return nil, err
		}
		role, roleVisible, err := s.resolveRoleForScope(tenantCtx, user.TenantID, binding.RoleID)
		if err != nil {
			return nil, err
		}
		roleName := fmt.Sprintf("角色 #%d", binding.RoleID)
		roleCode := ""
		namespaceScopeID := int64(0)
		permissions := []string{}
		if role == nil {
			roleName = fmt.Sprintf("已删除角色 #%d", binding.RoleID)
		} else if !roleVisible {
			roleName = fmt.Sprintf("不可见角色 #%d", binding.RoleID)
		} else {
			roleName = role.Name
			roleCode = role.Code
			namespaceScopeID = role.NamespaceScopeID
			permissions = append([]string(nil), role.Permissions...)
		}
		detail := &svc.UserRoleBindingDetail{
			BindingID:        binding.BindingID,
			UserID:           userID,
			RoleID:           binding.RoleID,
			RoleName:         roleName,
			RoleCode:         roleCode,
			GrantScopeID:     binding.GrantScopeID,
			NamespaceScopeID: namespaceScopeID,
			Permissions:      permissions,
			Status:           binding.Status,
		}
		if s.scopeAuthorizer != nil {
			if grantScope, err := s.scopeAuthorizer.Scope(tenantCtx, binding.GrantScopeID); err == nil && grantScope != nil {
				detail.GrantScopeKey = grantScope.Key
				detail.GrantScopeKind = grantScope.Type
			}
			if roleVisible && role != nil && role.NamespaceScopeID > 0 {
				if namespaceScope, err := s.scopeAuthorizer.Scope(tenantCtx, role.NamespaceScopeID); err == nil && namespaceScope != nil {
					detail.NamespaceScopeKey = namespaceScope.Key
					detail.NamespaceScopeKind = namespaceScope.Type
				}
			}
		}
		result = append(result, detail)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].GrantScopeID != result[j].GrantScopeID {
			return result[i].GrantScopeID < result[j].GrantScopeID
		}
		if result[i].RoleName != result[j].RoleName {
			return result[i].RoleName < result[j].RoleName
		}
		return result[i].BindingID < result[j].BindingID
	})
	return result, nil
}

func (s *UserService) resolveRoleForScope(ctx context.Context, tenantID string, roleID int64) (*iamentity.Role, bool, error) {
	role, err := s.roleRepo.Get(ctx, roleID)
	if err == nil {
		return role, true, nil
	}
	if !errors.Is(err, errors.NotFound) {
		return nil, false, err
	}
	tenantGlobalCtx, bindErr := svc.BindTenantGlobalScopeContext(ctx, tenantID)
	if bindErr != nil {
		return nil, false, bindErr
	}
	role, err = s.roleRepo.Get(tenantGlobalCtx, roleID)
	if err == nil {
		return role, false, nil
	}
	if errors.Is(err, errors.NotFound) {
		return nil, false, nil
	}
	return nil, false, err
}

// UserGroups 获取用户所属组织
func (s *UserService) UserGroups(ctx context.Context, userID int64) ([]*iamentity.Group, error) {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.RequireTenantPermission(ctx, s.scopeAuthorizer, svc.UserPermissionSet.Code(iammw.ActionRead), user.TenantID); err != nil {
		return nil, err
	}
	return s.groupRepo.FindByUserID(tenantCtx, userID)
}

// UserProfile 获取包含关联数据的用户信息
func (s *UserService) UserProfile(ctx context.Context, userID int64) (*iamentity.User, error) {
	user, tenantCtx, err := svc.LoadTenantBoundResource(ctx, s.userRepo, userID)
	if err != nil {
		return nil, err
	}
	user, err = s.userRepo.FindWithRelations(tenantCtx, userID)
	if err != nil {
		return nil, err
	}
	if _, err := svc.PreflightTenant(ctx, s.scopeAuthorizer, user.TenantID, ""); err != nil {
		return nil, err
	}
	return user, nil
}

// BatchAssignToGroup 批量将用户加入组织
func (s *UserService) BatchAssignToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error) {
	response := &svc.BatchOperationResponse{}

	for _, userID := range userIDs {
		if err := s.AssignToGroup(ctx, userID, groupID); err != nil {
			response.FailureCount++
			response.Errors = append(response.Errors, err)
		} else {
			response.SuccessCount++
		}
	}

	return response, nil
}

// 私有辅助方法

// validateRegisterRequest 验证注册请求
func (s *UserService) validateRegisterRequest(req *svc.RegisterRequest) error {
	if req.Username == "" {
		return errors.NewCode(errors.Validation, "用户名不能为空")
	}
	if len(req.Username) < svc.MinUsernameLength || len(req.Username) > svc.MaxUsernameLength {
		return errors.NewCode(errors.Validation, "用户名长度必须在3-50个字符之间")
	}
	if req.Email == "" {
		return errors.NewCode(errors.Validation, "邮箱不能为空")
	}
	if req.Password == "" {
		return errors.NewCode(errors.Validation, "密码不能为空")
	}
	if len(req.Password) < svc.MinPasswordLength {
		return errors.NewCode(errors.Validation, "密码长度不能少于6个字符")
	}
	// 可选：添加更强的密码策略
	// - 至少包含一个大写字母
	// - 至少包含一个小写字母
	// - 至少包含一个数字
	return nil
}

// hashPassword 加密密码
// 使用 bcrypt 算法，自动加盐，防止彩虹表攻击
func (s *UserService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// verifyPassword 验证密码
func (s *UserService) verifyPassword(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (s *UserService) updateUserWithGuard(ctx context.Context, user *iamentity.User) error {
	guard, err := svc.NewEntityWriteConstraint(ctx, svc.UserResourceKind, user)
	if err != nil {
		return err
	}
	return s.userRepo.UpdateWithConstraint(ctx, user, guard)
}

func (s *UserService) updateUserWithAuthorization(
	ctx context.Context,
	permission string,
	user *iamentity.User,
	mutate func(),
) error {
	guard, err := svc.AuthorizeWriteConstraint(ctx, s.authorizer, permission, user)
	if err != nil {
		return err
	}
	mutate()
	return s.userRepo.UpdateWithConstraint(ctx, user, guard)
}

// assignDefaultRole 分配默认角色
func (s *UserService) assignDefaultRole(ctx context.Context, tenantID string, userID int64) error {
	tenantID, err := svc.NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}

	// 查找默认用户角色
	role, err := s.roleRepo.FindByName(tenantCtx, svc.UserRoleName)
	if err != nil {
		return err
	}

	return s.userRepo.AssignRole(tenantCtx, userID, role.GetID())
}
