package service

import (
	"context"
	"strings"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	auth "gochen/auth"
	"gochen/errors"
	"gochen/validate"
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
//
// tenantID 从上下文中获取，而非从请求体中获取，以防止客户端伪造。
func (v *BusinessValidator) ValidateUserRegistration(ctx context.Context, tenantID string, req *RegisterRequest) error {
	// 1. 基础字段验证
	if err := v.validateUserBasicFields(req.Username, req.Email, req.Password); err != nil {
		return err
	}

	// 2. 租户ID验证
	tenantID, err := NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	tenantCtx, err := BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}

	// 3. 用户名唯一性验证
	if err := v.validateUsernameUniqueness(tenantCtx, req.Username); err != nil {
		return err
	}

	// 4. 邮箱唯一性验证
	if err := v.validateEmailUniqueness(tenantCtx, req.Email); err != nil {
		return err
	}

	// 5. 密码强度验证
	if err := v.validatePasswordStrength(req.Password); err != nil {
		return err
	}

	return nil
}

// ValidateUserUpdate 验证用户更新业务规则
func (v *BusinessValidator) ValidateUserUpdate(ctx context.Context, userID int64, req *UpdateUserRequest) error {
	// 1. 用户是否存在
	user, _, err := LoadTenantBoundResource(ctx, v.userRepo, userID)
	if err != nil {
		return err
	}

	// 2. 邮箱唯一性验证（如果更改了邮箱）
	if req.Email != "" && req.Email != user.Email {
		tenantCtx, bindErr := BindTenantContext(ctx, user.TenantID)
		if bindErr != nil {
			return bindErr
		}
		if err := v.validateEmailUniqueness(tenantCtx, req.Email); err != nil {
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
	user, tenantCtx, err := LoadTenantBoundResource(ctx, v.userRepo, userID)
	if err != nil {
		return err
	}
	if _, err := PreflightTenant(ctx, nil, user.TenantID, ""); err != nil {
		return err
	}

	// 2. 检查删除后是否还会保留同作用域的管理员能力
	roles, err := ResolveEffectiveRolesForUser(tenantCtx, userID, v.roleRepo, v.groupRepo)
	if err != nil {
		return err
	}
	protectedScopes := adminNamespaceScopes(roles)
	if len(protectedScopes) > 0 {
		activeRoles, err := v.roleRepo.FindByStatus(tenantCtx, RoleStatusActive)
		if err != nil {
			return err
		}
		remainingAdmins, err := v.remainingAdminUserIDs(tenantCtx, userID, activeRoles, protectedScopes)
		if err != nil {
			return err
		}
		if len(remainingAdmins) == 0 {
			return errors.NewCode(errors.Validation, "不能删除最后一个管理员")
		}
	}

	// 3. 检查用户是否有重要的业务关联
	// 这里可以添加更多业务规则，比如检查用户是否有未完成的任务等

	return nil
}

func (v *BusinessValidator) remainingAdminUserIDs(
	ctx context.Context,
	excludedUserID int64,
	roles []*iamentity.Role,
	protectedScopes map[int64]struct{},
) (map[int64]struct{}, error) {
	remaining := make(map[int64]struct{})
	for _, role := range roles {
		if !roleMatchesProtectedAdminScope(role, protectedScopes) {
			continue
		}
		users, err := v.userRepo.FindByRoleID(ctx, role.GetID())
		if err != nil {
			return nil, err
		}
		for _, user := range users {
			if user == nil || user.GetID() <= 0 || user.GetID() == excludedUserID {
				continue
			}
			remaining[user.GetID()] = struct{}{}
		}

		groups, err := v.groupRepo.FindByDefaultRoleID(ctx, role.GetID())
		if err != nil {
			return nil, err
		}
		for _, group := range groups {
			if group == nil || group.GetID() <= 0 {
				continue
			}
			groupUsers, err := v.userRepo.FindByGroupID(ctx, group.GetID())
			if err != nil {
				return nil, err
			}
			for _, user := range groupUsers {
				if user == nil || user.GetID() <= 0 || user.GetID() == excludedUserID {
					continue
				}
				remaining[user.GetID()] = struct{}{}
			}
		}
	}
	return remaining, nil
}

func adminNamespaceScopes(roles []*iamentity.Role) map[int64]struct{} {
	scopes := make(map[int64]struct{})
	for _, role := range roles {
		if !roleHasAdminCapability(role) {
			continue
		}
		scopes[role.NamespaceScopeID] = struct{}{}
	}
	return scopes
}

func roleMatchesProtectedAdminScope(role *iamentity.Role, protectedScopes map[int64]struct{}) bool {
	if !roleHasAdminCapability(role) || len(protectedScopes) == 0 {
		return false
	}
	_, ok := protectedScopes[role.NamespaceScopeID]
	return ok
}

func roleHasAdminCapability(role *iamentity.Role) bool {
	if role == nil || !role.IsActive() {
		return false
	}
	for _, permission := range role.Permissions {
		permission = strings.TrimSpace(permission)
		if permission == "" {
			continue
		}
		if auth.PermissionPatternMatches(permission, AdminEntryPermission.Code) {
			return true
		}
	}
	return false
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

	// 3. 同级组织名称唯一性验证（租户内）
	tenantID, err := NormalizeTenantID(ctx, req.TenantID)
	if err != nil {
		return err
	}
	if err := v.validateGroupNameUniqueness(ctx, tenantID, req.Name, req.ParentID); err != nil {
		return err
	}

	return nil
}

// ValidateGroupUpdate 验证组织更新业务规则。
func (v *BusinessValidator) ValidateGroupUpdate(
	ctx context.Context,
	groupID int64,
	req *UpdateGroupRequest,
	patches ...FieldPatch[iamentity.Group],
) error {
	if req == nil {
		return errors.NewCode(errors.Validation, "update group request is required")
	}

	// 1. 组织是否存在
	group, _, err := LoadTenantBoundResource(ctx, v.groupRepo, groupID)
	if err != nil {
		return err
	}

	candidate := *group
	if req.Name != "" {
		candidate.Name = req.Name
	}
	if req.Description != "" {
		candidate.Description = req.Description
	}
	if err := ApplyFieldPatches(&candidate, patches...); err != nil {
		return err
	}

	// 2. 名称唯一性验证（如果更改了名称，租户内）
	if candidate.Name != group.Name {
		if err := v.validateGroupNameUniqueness(ctx, group.TenantID, candidate.Name, candidate.ParentID); err != nil {
			return err
		}
	}

	// 3. 父组织变更验证
	if !sameInt64Ptr(group.ParentID, candidate.ParentID) {
		if err := v.validateGroupParentChange(ctx, group, candidate.ParentID); err != nil {
			return err
		}
	}

	return nil
}

// ValidateGroupDeletion 验证组织删除业务规则
func (v *BusinessValidator) ValidateGroupDeletion(ctx context.Context, tenantID string, groupID int64) error {
	tenantID, err := NormalizeTenantID(ctx, tenantID)
	if err != nil {
		return err
	}
	tenantCtx, err := BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	// 1. 组织是否存在
	_, _, err = LoadTenantBoundResource(ctx, v.groupRepo, groupID)
	if err != nil {
		return err
	}

	// 2. 检查是否有子组织
	children, err := v.groupRepo.FindChildren(tenantCtx, groupID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return errors.NewCode(errors.Validation, "不能删除有子组织的组织")
	}

	// 3. 检查是否有用户
	users, err := v.userRepo.FindByGroupID(tenantCtx, groupID)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return errors.NewCode(errors.Validation, "不能删除有用户的组织")
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
	tenantID, err := NormalizeTenantID(ctx, req.TenantID)
	if err != nil {
		return err
	}
	if err := v.validateRoleNameUniqueness(ctx, tenantID, req.Name); err != nil {
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
	role, _, err := LoadTenantBoundResource(ctx, v.roleRepo, roleID)
	if err != nil {
		return err
	}

	// 2. 系统角色不能修改
	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色不能被修改")
	}

	// 3. 名称唯一性验证（如果更改了名称）
	if req.Name != "" && req.Name != role.Name {
		if err := v.validateRoleNameUniqueness(ctx, role.TenantID, req.Name); err != nil {
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
	role, tenantCtx, err := LoadTenantBoundResource(ctx, v.roleRepo, roleID)
	if err != nil {
		return err
	}
	if _, err := PreflightTenant(ctx, nil, role.TenantID, ""); err != nil {
		return err
	}

	// 2. 系统角色不能删除
	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色不能被删除")
	}

	// 3. 检查是否正在使用中
	userCount, err := v.userRepo.CountByRoleID(tenantCtx, roleID)
	if err != nil {
		return err
	}
	if userCount > 0 {
		return errors.NewCode(errors.Validation, "角色正在被用户使用，不能删除")
	}
	groupCount, err := v.roleRepo.CountGroupsByRoleID(tenantCtx, roleID)
	if err != nil {
		return err
	}
	if groupCount > 0 {
		return errors.NewCode(errors.Validation, "角色正在使用中，不能删除")
	}

	return nil
}

// 私有验证方法

// validateUserBasicFields 验证用户基础字段
func (v *BusinessValidator) validateUserBasicFields(username, email, password string) error {
	if err := validate.Required(username, "username"); err != nil {
		return errors.NewCode(errors.Validation, "用户名不能为空")
	}
	if err := validate.StringLength(username, "username", MinUsernameLength, MaxUsernameLength); err != nil {
		return errors.NewCode(errors.Validation, "用户名长度必须在3-50个字符之间")
	}
	if err := validate.Required(email, "email"); err != nil {
		return errors.NewCode(errors.Validation, "邮箱不能为空")
	}
	if err := validate.Email(email); err != nil {
		return errors.NewCode(errors.Validation, "邮箱格式不正确")
	}
	if err := validate.Required(password, "password"); err != nil {
		return errors.NewCode(errors.Validation, "密码不能为空")
	}
	if err := validate.StringLength(password, "password", MinPasswordLength, 0); err != nil {
		return errors.NewCode(errors.Validation, "密码长度不能少于6个字符")
	}
	return nil
}

// validateUsernameUniqueness 验证用户名唯一性（租户内）
func (v *BusinessValidator) validateUsernameUniqueness(ctx context.Context, username string) error {
	existingUser, err := v.userRepo.FindByUsername(ctx, username)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return errors.Wrap(err, errors.Database, "检查用户名失败")
	}
	if existingUser != nil {
		return errors.NewCode(errors.Validation, "用户名已存在")
	}
	return nil
}

// validateEmailUniqueness 验证邮箱唯一性（租户内）
func (v *BusinessValidator) validateEmailUniqueness(ctx context.Context, email string) error {
	existingUser, err := v.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return errors.Wrap(err, errors.Database, "检查邮箱失败")
	}
	if existingUser != nil {
		return errors.NewCode(errors.Validation, "邮箱已存在")
	}
	return nil
}

// validatePasswordStrength 验证密码强度
func (v *BusinessValidator) validatePasswordStrength(password string) error {
	// 基础长度检查
	if err := validate.StringLength(password, "password", MinPasswordLength, 0); err != nil {
		return errors.NewCode(errors.Validation, "密码长度不能少于6个字符")
	}
	if err := validate.StringLength(password, "password", 0, MaxPasswordLength); err != nil {
		return errors.NewCode(errors.Validation, "密码长度不能超过255个字符")
	}

	// 可以添加更多密码强度规则
	// 例如：必须包含大小写字母、数字、特殊字符等

	return nil
}

// validateAvatarURL 验证头像URL
func (v *BusinessValidator) validateAvatarURL(avatar string) error {
	if err := validate.StringLength(avatar, "avatar", 0, 500); err != nil {
		return errors.NewCode(errors.Validation, "头像URL长度不能超过500个字符")
	}
	// 可以添加URL格式验证
	return nil
}

// validateGroupBasicFields 验证组织基础字段
func (v *BusinessValidator) validateGroupBasicFields(name, description string) error {
	if err := validate.Required(name, "group name"); err != nil {
		return errors.NewCode(errors.Validation, "组织名称不能为空")
	}
	if err := validate.StringLength(name, "group name", 0, 100); err != nil {
		return errors.NewCode(errors.Validation, "组织名称不能超过100个字符")
	}
	if err := validate.StringLength(description, "group description", 0, 500); err != nil {
		return errors.NewCode(errors.Validation, "组织描述不能超过500个字符")
	}
	return nil
}

// validateParentGroup 验证父组织
func (v *BusinessValidator) validateParentGroup(ctx context.Context, parentID int64) error {
	parent, _, err := LoadTenantBoundResource(ctx, v.groupRepo, parentID)
	if err != nil {
		return errors.Wrap(err, errors.NotFound, "父组织不存在")
	}
	if parent.Level >= MaxGroupLevel {
		return errors.NewCode(errors.Validation, "组织层级不能超过10级")
	}
	return nil
}

// validateGroupNameUniqueness 验证组织名称唯一性（同级，租户内）
func (v *BusinessValidator) validateGroupNameUniqueness(ctx context.Context, tenantID string, name string, parentID *int64) error {
	var (
		groups []*iamentity.Group
		err    error
	)

	if parentID == nil {
		tenantCtx, bindErr := BindTenantContext(ctx, tenantID)
		if bindErr != nil {
			return bindErr
		}
		groups, err = v.groupRepo.FindRootGroups(tenantCtx)
	} else {
		tenantCtx, bindErr := BindTenantContext(ctx, tenantID)
		if bindErr != nil {
			return bindErr
		}
		groups, err = v.groupRepo.FindChildren(tenantCtx, *parentID)
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

// validateGroupParentChange 验证组织父级变更
func (v *BusinessValidator) validateGroupParentChange(ctx context.Context, group *iamentity.Group, newParentID *int64) error {
	if newParentID != nil {
		// 不能设置为自己
		if *newParentID == group.GetID() {
			return errors.NewCode(errors.Validation, "不能将组织设置为自己的父组织")
		}

		// 检查新父组织是否存在
		newParent, tenantCtx, err := LoadTenantBoundResource(ctx, v.groupRepo, *newParentID)
		if err != nil {
			return errors.Wrap(err, errors.NotFound, "新父组织不存在")
		}
		if _, err := PreflightSameTenant(tenantCtx, nil, "", group.TenantID, newParent.TenantID); err != nil {
			return err
		}

		// 不能设置为自己的子组织
		if newParent.IsDescendantOf(group) {
			return errors.NewCode(errors.Validation, "不能将组织移动到其子组织下")
		}

		// 检查新父组织层级
		if newParent.Level >= MaxGroupLevel {
			return errors.NewCode(errors.Validation, "目标组织层级过深")
		}
	}
	return nil
}

// validateRoleBasicFields 验证角色基础字段
func (v *BusinessValidator) validateRoleBasicFields(name, description string) error {
	if err := validate.Required(name, "role name"); err != nil {
		return errors.NewCode(errors.Validation, "角色名称不能为空")
	}
	if err := validate.StringLength(name, "role name", 0, 50); err != nil {
		return errors.NewCode(errors.Validation, "角色名称不能超过50个字符")
	}
	if err := validate.StringLength(description, "role description", 0, 500); err != nil {
		return errors.NewCode(errors.Validation, "角色描述不能超过500个字符")
	}
	return nil
}

// validateRoleNameUniqueness 验证角色名称唯一性（租户内）
func (v *BusinessValidator) validateRoleNameUniqueness(ctx context.Context, tenantID, name string) error {
	tenantCtx, err := BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	existingRole, err := v.roleRepo.FindByName(tenantCtx, name)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return errors.Wrap(err, errors.Database, "检查角色名称失败")
	}
	if existingRole != nil {
		return errors.NewCode(errors.Validation, "角色名称已存在")
	}
	return nil
}

// validatePermissions 验证权限列表
func (v *BusinessValidator) validatePermissions(permissions []string) error {
	if len(permissions) == 0 {
		return errors.NewCode(errors.Validation, "角色必须至少拥有一个权限")
	}
	for _, permission := range permissions {
		if !v.isValidPermission(permission) {
			return errors.NewCode(errors.Validation, "无效的权限: "+permission)
		}
	}
	return nil
}

// isValidEmail 验证邮箱格式
// isValidPermission 检查权限是否有效
func (v *BusinessValidator) isValidPermission(permission string) bool {
	for _, validPerm := range AllPermissions {
		if permission == validPerm {
			return true
		}
	}
	return iammw.IsValidPermissionCode(permission)
}
