package user

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	iamentity "gochen-iam/entity"

	grouprepo "gochen-iam/repo/group"

	rolerepo "gochen-iam/repo/role"

	userrepo "gochen-iam/repo/user"

	svc "gochen-iam/service"
	"gochen/errorx"
	"gochen/logging"
)

// UserService 用户服务
type UserService struct {
	userRepo  *userrepo.UserRepo
	groupRepo *grouprepo.GroupRepo
	roleRepo  *rolerepo.RoleRepo
	logger    logging.ILogger
}

// NewUserService 创建用户服务实例
func NewUserService(
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
) *UserService {
	return &UserService{
		userRepo:  userRepo,
		groupRepo: groupRepo,
		roleRepo:  roleRepo,
		logger:    logging.ComponentLogger("iam.service.user"),
	}
}

// Register 用户注册
func (s *UserService) Register(ctx context.Context, req *svc.RegisterRequest) (*iamentity.User, error) {
	// 1. 验证请求数据
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// 2. 检查用户名是否已存在
	existingUser, err := s.userRepo.FindByUsername(ctx, req.Username)
	if err != nil && !errorx.Is(err, errorx.NotFound) {
		return nil, errorx.Wrap(err, errorx.Database, "检查用户名失败")
	}
	if existingUser != nil {
		return nil, errorx.New(errorx.Validation, "用户名已存在")
	}

	// 3. 检查邮箱是否已存在
	existingUser, err = s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil && !errorx.Is(err, errorx.NotFound) {
		return nil, errorx.Wrap(err, errorx.Database, "检查邮箱失败")
	}
	if existingUser != nil {
		return nil, errorx.New(errorx.Validation, "邮箱已存在")
	}

	// 4. 创建用户实体
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errorx.Wrap(err, errorx.Internal, "密码加密失败")
	}

	user := &iamentity.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		Status:   svc.UserStatusActive,
	}
	user.SetUpdatedAt(time.Now())

	// 5. 保存用户
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "保存用户失败")
	}

	// 6. 分配默认角色
	if err := s.assignDefaultRole(ctx, user.GetID()); err != nil {
		// 记录错误但不影响注册流程
		s.logger.Warn(ctx, "[UserService] 分配默认角色失败",
			logging.Error(err),
			logging.Int64("user_id", user.GetID()),
			logging.String("username", user.Username),
		)
	}

	return user, nil
}

// Authenticate 用户认证（不包含 token；token 由协议层按配置生成）。
func (s *UserService) Authenticate(ctx context.Context, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error) {
	// 1. 验证请求数据
	if req == nil {
		return nil, errorx.New(errorx.Validation, "请求不能为空")
	}
	if req.Username == "" || req.Password == "" {
		return nil, errorx.New(errorx.Validation, "用户名和密码不能为空")
	}

	// 2. 查找用户
	user, err := s.userRepo.FindByUsername(ctx, req.Username)
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "用户名或密码错误")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}

	// 3. 验证密码
	if !s.verifyPassword(req.Password, user.Password) {
		return nil, errorx.New(errorx.Validation, "用户名或密码错误")
	}

	// 4. 检查用户状态
	if !user.IsActive() {
		return nil, errorx.New(errorx.Validation, "用户账户已被禁用")
	}

	// 5. 更新最后登录时间
	user.UpdateLastLogin()
	if err := s.userRepo.Update(ctx, user); err != nil {
		// 记录错误但不影响登录流程
		s.logger.Warn(ctx, "[UserService] 更新最后登录时间失败",
			logging.Error(err),
			logging.Int64("user_id", user.GetID()),
			logging.String("username", user.Username),
		)
	}

	// 6. 返回认证结果（不包含 token）
	roles, permissions, err := s.resolveEffectiveRolesAndPermissions(ctx, user.GetID())
	if err != nil {
		return nil, err
	}

	return &svc.AuthenticateResult{
		UserID:      user.GetID(),
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

// GetAuthSnapshot 返回用于签发/刷新 token 的最新身份快照（角色 + 权限）。
//
// 说明：
// - 仅返回“有效角色”：已软删除角色与非 active 角色会被过滤；
// - 若用户不存在或已禁用，返回错误，由调用方决定如何映射为 HTTP 错误码。
func (s *UserService) GetAuthSnapshot(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errorx.New(errorx.Validation, "用户账户已被禁用")
	}

	roles, permissions, err := s.resolveEffectiveRolesAndPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &svc.AuthenticateResult{
		UserID:      user.GetID(),
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

func (s *UserService) resolveEffectiveRolesAndPermissions(ctx context.Context, userID int64) ([]string, []string, error) {
	roles, err := s.roleRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	roleNames := make([]string, 0, len(roles))
	roleSet := make(map[string]struct{}, len(roles))

	permissions := make([]string, 0, len(roles)*2)
	permissionSet := make(map[string]struct{}, len(roles)*2)

	for i := range roles {
		role := roles[i]
		if role == nil {
			continue
		}
		if role.Status != svc.RoleStatusActive {
			continue
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
			if _, exists := permissionSet[permission]; exists {
				continue
			}
			permissionSet[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}

	// 固定输出顺序，避免测试与 token 声明受数据库返回顺序影响。
	sort.Strings(roleNames)
	sort.Strings(permissions)

	return roleNames, permissions, nil
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(ctx context.Context, userID int64, req *svc.ChangePasswordRequest) error {
	// 1. 获取用户
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. 验证旧密码
	if !s.verifyPassword(req.OldPassword, user.Password) {
		return errorx.New(errorx.Validation, "原密码错误")
	}

	// 3. 验证新密码
	if len(req.NewPassword) < svc.MinPasswordLength {
		return errorx.New(errorx.Validation, "新密码长度不能少于6个字符")
	}

	// 4. 更新密码
	hashedPassword, err := s.hashPassword(req.NewPassword)
	if err != nil {
		return errorx.Wrap(err, errorx.Internal, "密码加密失败")
	}
	user.Password = hashedPassword
	user.SetUpdatedAt(time.Now())

	return s.userRepo.Update(ctx, user)
}

// UpdateProfile 更新用户资料
func (s *UserService) UpdateProfile(ctx context.Context, userID int64, req *svc.UpdateUserRequest) (*iamentity.User, error) {
	// 1. 获取用户
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// 2. 更新字段
	if req.Email != "" && req.Email != user.Email {
		// 检查邮箱是否已被使用
		existingUser, err := s.userRepo.FindByEmail(ctx, req.Email)
		if err != nil && !errorx.Is(err, errorx.NotFound) {
			return nil, errorx.Wrap(err, errorx.Database, "检查邮箱失败")
		}
		if existingUser != nil && existingUser.GetID() != userID {
			return nil, errorx.New(errorx.Validation, "邮箱已被使用")
		}
		user.Email = req.Email
	}

	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}

	user.SetUpdatedAt(time.Now())

	// 3. 保存更新
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// ActivateUser 激活用户
func (s *UserService) ActivateUser(ctx context.Context, userID int64) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Activate()
	return s.userRepo.Update(ctx, user)
}

// DeactivateUser 停用用户
func (s *UserService) DeactivateUser(ctx context.Context, userID int64) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Deactivate()
	return s.userRepo.Update(ctx, user)
}

// LockUser 锁定用户
func (s *UserService) LockUser(ctx context.Context, userID int64) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Lock()
	return s.userRepo.Update(ctx, user)
}

// UnlockUser 解锁用户
func (s *UserService) UnlockUser(ctx context.Context, userID int64) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Unlock()
	return s.userRepo.Update(ctx, user)
}

// AssignRole 为用户分配角色
func (s *UserService) AssignRole(ctx context.Context, userID, roleID int64) error {
	// 1. 检查用户是否存在
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. 检查角色是否存在
	_, err = s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 3. 分配角色
	return s.userRepo.AssignRole(ctx, userID, roleID)
}

// RemoveRole 移除用户角色
func (s *UserService) RemoveRole(ctx context.Context, userID, roleID int64) error {
	return s.userRepo.RemoveRole(ctx, userID, roleID)
}

// AssignToGroup 将用户分配到组织
func (s *UserService) AssignToGroup(ctx context.Context, userID, groupID int64) error {
	// 1. 检查用户是否存在
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. 检查组织是否存在
	_, err = s.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// 3. 分配到组织
	return s.userRepo.AssignToGroup(ctx, userID, groupID)
}

// RemoveFromGroup 从组织中移除用户
func (s *UserService) RemoveFromGroup(ctx context.Context, userID, groupID int64) error {
	return s.userRepo.RemoveFromGroup(ctx, userID, groupID)
}

// GetUserPermissions 获取用户权限
func (s *UserService) GetUserPermissions(ctx context.Context, userID int64) ([]string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return user.GetAllPermissions(), nil
}

// CheckPermission 检查用户权限
func (s *UserService) CheckPermission(ctx context.Context, userID int64, permission string) (bool, error) {
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permission {
			return true, nil
		}
	}

	return false, nil
}

// SearchUsers 搜索用户
func (s *UserService) SearchUsers(ctx context.Context, keyword string, limit int) ([]*iamentity.User, error) {
	return s.userRepo.SearchUsers(ctx, keyword, limit)
}

// GetUsersByStatus 根据状态获取用户
func (s *UserService) GetUsersByStatus(ctx context.Context, status string) ([]*iamentity.User, error) {
	return s.userRepo.FindByStatus(ctx, status)
}

// GetUserRoles 获取用户角色
func (s *UserService) GetUserRoles(ctx context.Context, userID int64) ([]*iamentity.Role, error) {
	return s.roleRepo.FindByUserID(ctx, userID)
}

// GetUserGroups 获取用户所属组织
func (s *UserService) GetUserGroups(ctx context.Context, userID int64) ([]*iamentity.Group, error) {
	return s.groupRepo.FindByUserID(ctx, userID)
}

// GetUserProfile 获取包含关联数据的用户信息
func (s *UserService) GetUserProfile(ctx context.Context, userID int64) (*iamentity.User, error) {
	return s.userRepo.GetWithRelations(ctx, userID)
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
		return errorx.New(errorx.Validation, "用户名不能为空")
	}
	if len(req.Username) < svc.MinUsernameLength || len(req.Username) > svc.MaxUsernameLength {
		return errorx.New(errorx.Validation, "用户名长度必须在3-50个字符之间")
	}
	if req.Email == "" {
		return errorx.New(errorx.Validation, "邮箱不能为空")
	}
	if req.Password == "" {
		return errorx.New(errorx.Validation, "密码不能为空")
	}
	if len(req.Password) < 8 {
		return errorx.New(errorx.Validation, "密码长度不能少于8个字符")
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

// assignDefaultRole 分配默认角色
func (s *UserService) assignDefaultRole(ctx context.Context, userID int64) error {
	// 查找默认用户角色
	role, err := s.roleRepo.FindByName(ctx, svc.UserRoleName)
	if err != nil {
		return err
	}

	return s.userRepo.AssignRole(ctx, userID, role.GetID())
}
