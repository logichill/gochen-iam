package service

import (
	"context"
	"regexp"
	"strings"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	"gochen/errors"
)

// BusinessValidator 业务规则验证器
type BusinessValidator struct {
	userRepo  *userrepo.UserRepo
	groupRepo *grouprepo.GroupRepo
	roleRepo  *rolerepo.RoleRepo
}

// NewBusinessValidator 创建业务验证器
func NewBusinessValidator(
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
) *BusinessValidator {
	return &BusinessValidator{
		userRepo:  userRepo,
		groupRepo: groupRepo,
		roleRepo:  roleRepo,
	}
}

// 用户相关业务规则验证

// ValidateUserRegistration 验证用户注册业务规则
func (v *BusinessValidator) ValidateUserRegistration(ctx context.Context, req *RegisterRequest) error {
	// 1. 基础字段验证
	if err := v.validateUserBasicFields(req.Username, req.Email, req.Password); err != nil {
		return err
	}

	// 2. 用户名唯一性验证
	if err := v.validateUsernameUniqueness(ctx, req.Username); err != nil {
		return err
	}

	// 3. 邮箱唯一性验证
	if err := v.validateEmailUniqueness(ctx, req.Email); err != nil {
		return err
	}

	// 4. 密码强度验证
	if err := v.validatePasswordStrength(req.Password); err != nil {
		return err
	}

	return nil
}

// ValidateUserUpdate 验证用户更新业务规则
func (v *BusinessValidator) ValidateUserUpdate(ctx context.Context, userID int64, req *UpdateUserRequest) error {
	// 1. 用户是否存在
	user, err := v.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. 邮箱唯一性验证（如果更改了邮箱）
	if req.Email != "" && req.Email != user.Email {
		if err := v.validateEmailUniqueness(ctx, req.Email); err != nil {
			return err
		}
	}

	// 3. 头像URL验证
	if req.Avatar != "" {
		if err := v.validateAvatarURL(req.Avatar); err != nil {
			return err
		}
	}

	return nil
}

// ValidateUserDeletion 验证用户删除业务规则
func (v *BusinessValidator) ValidateUserDeletion(ctx context.Context, userID int64) error {
	// 1. 用户是否存在
	user, err := v.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// 2. 检查是否为系统管理员
	if user.HasRole(SystemAdminRoleName) {
		// 检查是否为最后一个系统管理员
		adminUsers, err := v.userRepo.FindByRoleID(ctx, 1) // 假设系统管理员角色ID为1
		if err != nil {
			return err
		}
		if len(adminUsers) <= 1 {
			return errors.NewError(errors.ErrCodeValidation, "不能删除最后一个系统管理员")
		}
	}

	// 3. 检查用户是否有重要的业务关联
	// 这里可以添加更多业务规则，比如检查用户是否有未完成的任务等

	return nil
}

// 组织相关业务规则验证

// ValidateGroupCreation 验证组织创建业务规则
func (v *BusinessValidator) ValidateGroupCreation(ctx context.Context, req *CreateGroupRequest) error {
	// 1. 基础字段验证
	if err := v.validateGroupBasicFields(req.Name, req.Description); err != nil {
		return err
	}

	// 2. 父组织验证
	if req.ParentID != nil {
		if err := v.validateParentGroup(ctx, *req.ParentID); err != nil {
			return err
		}
	}

	// 3. 同级组织名称唯一性验证
	if err := v.validateGroupNameUniqueness(ctx, req.Name, req.ParentID); err != nil {
		return err
	}

	return nil
}

// ValidateGroupUpdate 验证组织更新业务规则
func (v *BusinessValidator) ValidateGroupUpdate(ctx context.Context, groupID int64, req *UpdateGroupRequest) error {
	// 1. 组织是否存在
	group, err := v.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// 2. 名称唯一性验证（如果更改了名称）
	if req.Name != "" && req.Name != group.Name {
		if err := v.validateGroupNameUniqueness(ctx, req.Name, group.ParentID); err != nil {
			return err
		}
	}

	// 3. 父组织变更验证
	if req.ParentID != nil && (group.ParentID == nil || *req.ParentID != *group.ParentID) {
		if err := v.validateGroupParentChange(ctx, group, req.ParentID); err != nil {
			return err
		}
	}

	return nil
}

// ValidateGroupDeletion 验证组织删除业务规则
func (v *BusinessValidator) ValidateGroupDeletion(ctx context.Context, groupID int64) error {
	// 1. 组织是否存在
	_, err := v.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		return err
	}

	// 2. 检查是否有子组织
	children, err := v.groupRepo.FindChildren(ctx, groupID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return errors.NewError(errors.ErrCodeValidation, "不能删除有子组织的组织")
	}

	// 3. 检查是否有用户
	users, err := v.userRepo.FindByGroupID(ctx, groupID)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errors.NewError(errors.ErrCodeValidation, "不能删除有用户的组织")
	}

	return nil
}

// 角色相关业务规则验证

// ValidateRoleCreation 验证角色创建业务规则
func (v *BusinessValidator) ValidateRoleCreation(ctx context.Context, req *CreateRoleRequest) error {
	// 1. 基础字段验证
	if err := v.validateRoleBasicFields(req.Name, req.Description); err != nil {
		return err
	}

	// 2. 角色名称唯一性验证
	if err := v.validateRoleNameUniqueness(ctx, req.Name); err != nil {
		return err
	}

	// 3. 权限验证
	if err := v.validatePermissions(req.Permissions); err != nil {
		return err
	}

	return nil
}

// ValidateRoleUpdate 验证角色更新业务规则
func (v *BusinessValidator) ValidateRoleUpdate(ctx context.Context, roleID int64, req *UpdateRoleRequest) error {
	// 1. 角色是否存在
	role, err := v.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 系统角色不能修改
	if role.IsSystem {
		return errors.NewError(errors.ErrCodeValidation, "系统角色不能被修改")
	}

	// 3. 名称唯一性验证（如果更改了名称）
	if req.Name != "" && req.Name != role.Name {
		if err := v.validateRoleNameUniqueness(ctx, req.Name); err != nil {
			return err
		}
	}

	// 4. 权限验证
	if len(req.Permissions) > 0 {
		if err := v.validatePermissions(req.Permissions); err != nil {
			return err
		}
	}

	return nil
}

// ValidateRoleDeletion 验证角色删除业务规则
func (v *BusinessValidator) ValidateRoleDeletion(ctx context.Context, roleID int64) error {
	// 1. 角色是否存在
	role, err := v.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 2. 系统角色不能删除
	if role.IsSystem {
		return errors.NewError(errors.ErrCodeValidation, "系统角色不能被删除")
	}

	// 3. 检查是否正在使用中
	if role.IsInUse() {
		return errors.NewError(errors.ErrCodeValidation, "角色正在使用中，不能删除")
	}

	return nil
}

// 私有验证方法

// validateUserBasicFields 验证用户基础字段
func (v *BusinessValidator) validateUserBasicFields(username, email, password string) error {
	if username == "" {
		return errors.NewError(errors.ErrCodeValidation, "用户名不能为空")
	}
	if len(username) < MinUsernameLength || len(username) > MaxUsernameLength {
		return errors.NewError(errors.ErrCodeValidation, "用户名长度必须在3-50个字符之间")
	}
	if email == "" {
		return errors.NewError(errors.ErrCodeValidation, "邮箱不能为空")
	}
	if !v.isValidEmail(email) {
		return errors.NewError(errors.ErrCodeValidation, "邮箱格式不正确")
	}
	if password == "" {
		return errors.NewError(errors.ErrCodeValidation, "密码不能为空")
	}
	if len(password) < MinPasswordLength {
		return errors.NewError(errors.ErrCodeValidation, "密码长度不能少于6个字符")
	}
	return nil
}

// validateUsernameUniqueness 验证用户名唯一性
func (v *BusinessValidator) validateUsernameUniqueness(ctx context.Context, username string) error {
	existingUser, err := v.userRepo.FindByUsername(ctx, username)
	if err != nil && !errors.IsNotFound(err) {
		return errors.WrapError(err, errors.ErrCodeDatabase, "检查用户名失败")
	}
	if existingUser != nil {
		return errors.NewError(errors.ErrCodeValidation, "用户名已存在")
	}
	return nil
}

// validateEmailUniqueness 验证邮箱唯一性
func (v *BusinessValidator) validateEmailUniqueness(ctx context.Context, email string) error {
	existingUser, err := v.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.IsNotFound(err) {
		return errors.WrapError(err, errors.ErrCodeDatabase, "检查邮箱失败")
	}
	if existingUser != nil {
		return errors.NewError(errors.ErrCodeValidation, "邮箱已存在")
	}
	return nil
}

// validatePasswordStrength 验证密码强度
func (v *BusinessValidator) validatePasswordStrength(password string) error {
	// 基础长度检查
	if len(password) < MinPasswordLength {
		return errors.NewError(errors.ErrCodeValidation, "密码长度不能少于6个字符")
	}
	if len(password) > MaxPasswordLength {
		return errors.NewError(errors.ErrCodeValidation, "密码长度不能超过255个字符")
	}

	// 可以添加更多密码强度规则
	// 例如：必须包含大小写字母、数字、特殊字符等

	return nil
}

// validateAvatarURL 验证头像URL
func (v *BusinessValidator) validateAvatarURL(avatar string) error {
	if len(avatar) > 500 {
		return errors.NewError(errors.ErrCodeValidation, "头像URL长度不能超过500个字符")
	}
	// 可以添加URL格式验证
	return nil
}

// validateGroupBasicFields 验证组织基础字段
func (v *BusinessValidator) validateGroupBasicFields(name, description string) error {
	if name == "" {
		return errors.NewError(errors.ErrCodeValidation, "组织名称不能为空")
	}
	if len(name) > 100 {
		return errors.NewError(errors.ErrCodeValidation, "组织名称不能超过100个字符")
	}
	if len(description) > 500 {
		return errors.NewError(errors.ErrCodeValidation, "组织描述不能超过500个字符")
	}
	return nil
}

// validateParentGroup 验证父组织
func (v *BusinessValidator) validateParentGroup(ctx context.Context, parentID int64) error {
	parent, err := v.groupRepo.GetByID(ctx, parentID)
	if err != nil {
		return errors.WrapError(err, errors.ErrCodeNotFound, "父组织不存在")
	}
	if parent.Level >= MaxGroupLevel {
		return errors.NewError(errors.ErrCodeValidation, "组织层级不能超过10级")
	}
	return nil
}

// validateGroupNameUniqueness 验证组织名称唯一性（同级）
func (v *BusinessValidator) validateGroupNameUniqueness(ctx context.Context, name string, parentID *int64) error {
	var (
		groups []*iamentity.Group
		err    error
	)

	if parentID == nil {
		groups, err = v.groupRepo.FindRootGroups(ctx)
	} else {
		groups, err = v.groupRepo.FindChildren(ctx, *parentID)
	}
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group.Name == name {
			return errors.NewError(errors.ErrCodeValidation, "同一层级下组织名称不能重复")
		}
	}
	return nil
}

// validateGroupParentChange 验证组织父级变更
func (v *BusinessValidator) validateGroupParentChange(ctx context.Context, group *iamentity.Group, newParentID *int64) error {
	if newParentID != nil {
		// 不能设置为自己
		if *newParentID == group.GetID() {
			return errors.NewError(errors.ErrCodeValidation, "不能将组织设置为自己的父组织")
		}

		// 检查新父组织是否存在
		newParent, err := v.groupRepo.GetByID(ctx, *newParentID)
		if err != nil {
			return errors.WrapError(err, errors.ErrCodeNotFound, "新父组织不存在")
		}

		// 不能设置为自己的子组织
		if newParent.IsDescendantOf(group) {
			return errors.NewError(errors.ErrCodeValidation, "不能将组织移动到其子组织下")
		}

		// 检查新父组织层级
		if newParent.Level >= MaxGroupLevel {
			return errors.NewError(errors.ErrCodeValidation, "目标组织层级过深")
		}
	}
	return nil
}

// validateRoleBasicFields 验证角色基础字段
func (v *BusinessValidator) validateRoleBasicFields(name, description string) error {
	if name == "" {
		return errors.NewError(errors.ErrCodeValidation, "角色名称不能为空")
	}
	if len(name) > 50 {
		return errors.NewError(errors.ErrCodeValidation, "角色名称不能超过50个字符")
	}
	if len(description) > 500 {
		return errors.NewError(errors.ErrCodeValidation, "角色描述不能超过500个字符")
	}
	return nil
}

// validateRoleNameUniqueness 验证角色名称唯一性
func (v *BusinessValidator) validateRoleNameUniqueness(ctx context.Context, name string) error {
	existingRole, err := v.roleRepo.FindByName(ctx, name)
	if err != nil && !errors.IsNotFound(err) {
		return errors.WrapError(err, errors.ErrCodeDatabase, "检查角色名称失败")
	}
	if existingRole != nil {
		return errors.NewError(errors.ErrCodeValidation, "角色名称已存在")
	}
	return nil
}

// validatePermissions 验证权限列表
func (v *BusinessValidator) validatePermissions(permissions []string) error {
	if len(permissions) == 0 {
		return errors.NewError(errors.ErrCodeValidation, "角色必须至少拥有一个权限")
	}
	for _, permission := range permissions {
		if !v.isValidPermission(permission) {
			return errors.NewError(errors.ErrCodeValidation, "无效的权限: "+permission)
		}
	}
	return nil
}

// isValidEmail 验证邮箱格式
func (v *BusinessValidator) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// isValidPermission 检查权限是否有效
func (v *BusinessValidator) isValidPermission(permission string) bool {
	for _, validPerm := range AllPermissions {
		if permission == validPerm {
			return true
		}
	}
	// 支持通配符权限
	return strings.Contains(permission, ":") && len(permission) > 3
}
