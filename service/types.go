package service

import "encoding/json"

import iammw "gochen-iam/middleware"

// 用户相关请求和响应类型

// RegisterRequest 用户注册请求
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// AuthenticateRequest 用户认证请求
type AuthenticateRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AuthenticateResult 用户认证结果（不包含 token；token 由协议层按配置生成）。
type AuthenticateResult struct {
	UserID      int64    `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// UpdateUserRequest 更新用户信息请求
type UpdateUserRequest struct {
	Email  string `json:"email" binding:"omitempty,email"`
	Avatar string `json:"avatar" binding:"omitempty"`
}

// 组织相关请求和响应类型

// CreateGroupRequest 创建组织请求
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
	ParentID    *int64 `json:"parent_id" binding:"omitempty"`
}

// UpdateGroupRequest 更新组织请求
type UpdateGroupRequest struct {
	Name        string `json:"name" binding:"omitempty,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
	ParentID    *int64 `json:"parent_id" binding:"omitempty"`
	ParentIDSet bool   `json:"-"`
}

// UnmarshalJSON 区分 parent_id 缺失与显式传 null 的场景。
func (r *UpdateGroupRequest) UnmarshalJSON(data []byte) error {
	type alias UpdateGroupRequest
	var payload struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		ParentID    *int64 `json:"parent_id"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*r = UpdateGroupRequest{
		Name:        payload.Name,
		Description: payload.Description,
		ParentID:    payload.ParentID,
	}
	_, r.ParentIDSet = raw["parent_id"]
	return nil
}

// GroupTreeNode 组织树节点
type GroupTreeNode struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Level       int              `json:"level"`
	UserCount   int              `json:"user_count"`
	Children    []*GroupTreeNode `json:"children,omitempty"`
}

// 角色相关请求和响应类型

// CreateRoleRequest 定义创建角色请求参数。
type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required,max=50"`
	Description string   `json:"description" binding:"omitempty,max=500"`
	Permissions []string `json:"permissions" binding:"required"`
}

// UpdateRoleRequest 定义Update角色请求参数。
type UpdateRoleRequest struct {
	Name        string   `json:"name" binding:"omitempty,max=50"`
	Description string   `json:"description" binding:"omitempty,max=500"`
	Permissions []string `json:"permissions" binding:"omitempty"`
}

// RoleAssignRequest 角色分配请求
type RoleAssignRequest struct {
	UserIDs []int64 `json:"user_ids" binding:"required"`
	RoleID  int64   `json:"role_id" binding:"required"`
}

// PermissionCheckRequest 权限检查请求
type PermissionCheckRequest struct {
	UserID     int64  `json:"user_id" binding:"required"`
	Permission string `json:"permission" binding:"required"`
}

// PermissionCheckResponse 权限检查响应
type PermissionCheckResponse struct {
	HasPermission bool     `json:"has_permission"`
	Roles         []string `json:"roles"`
	Source        string   `json:"source"` // "direct" 或 "inherited"
}

// 通用响应类型

// BatchOperationRequest 批量操作请求
type BatchOperationRequest struct {
	IDs []int64 `json:"ids" binding:"required"`
}

// BatchOperationResponse 批量操作响应
type BatchOperationResponse struct {
	SuccessCount int     `json:"success_count"`
	FailureCount int     `json:"failure_count"`
	Errors       []error `json:"errors,omitempty"`
}

// StatisticsResponse 统计信息响应
type StatisticsResponse struct {
	TotalUsers    int64            `json:"total_users"`
	ActiveUsers   int64            `json:"active_users"`
	TotalGroups   int64            `json:"total_groups"`
	TotalRoles    int64            `json:"total_roles"`
	GroupsByLevel map[int]int64    `json:"groups_by_level"`
	UsersByStatus map[string]int64 `json:"users_by_status"`
}

// 业务规则常量

const (
	// 用户状态
	UserStatusActive   = "active"
	UserStatusInactive = "inactive"
	UserStatusLocked   = "locked"
	UserStatusPending  = "pending"

	// 角色状态
	RoleStatusActive   = "active"
	RoleStatusInactive = "inactive"

	// 系统角色名称
	SystemAdminRoleName = "system_admin"
	UserRoleName        = "user"

	// 业务限制
	MaxGroupLevel     = 10  // 最大组织层级
	MaxPasswordLength = 255 // 最大密码长度
	MinPasswordLength = 6   // 最小密码长度
	MaxUsernameLength = 50  // 最大用户名长度
	MinUsernameLength = 3   // 最小用户名长度
)

// 预定义权限
var (
	// 系统权限
	SystemPermissions = []string{
		"api:system:read",
		"api:system:write",
		"api:system:delete",
	}

	// 用户权限
	UserPermissions = []string{
		"api:user:read",
		"api:user:write",
		"api:user:delete",
		"api:user:read_self",
		"api:user:update_self",
	}

	// 组织权限
	GroupPermissions = []string{
		"api:group:read",
		"api:group:write",
		"api:group:delete",
	}

	// 任务权限
	TaskPermissions = []string{
		"api:task:read",
		"api:task:write",
		"api:task:delete",
	}

	// 积分权限
	PointsPermissions = []string{
		"api:points:read",
		"api:points:write",
	}

	// 等级权限
	LevelPermissions = []string{
		"api:level:read",
		"api:level:write",
	}

	// 计划权限
	PlanPermissions = []string{
		"api:plan:read",
		"api:plan:write",
	}

	// 角色权限
	RolePermissions = []string{
		"api:role:read",
		"api:role:write",
		"api:role:delete",
	}

	// 菜单权限（后台导航可见性配置）
	MenuPermissions = []string{
		"api:menu:read",
		"api:menu:write",
		"api:menu:publish",
	}

	// 动作权限（非 HTTP 资源型能力）。
	ActionPermissions = []string{
		"action:mcp:invoke",
	}

	// 菜单可见性权限是数据驱动的，使用通配定义兜住具体菜单 code。
	MenuVisibilityPermissionPatterns = []string{
		"menu:*:view",
	}

	// 所有权限
	AllPermissions = append(
		append(
			append(
				append(
					append(
						append(SystemPermissions, UserPermissions...),
						GroupPermissions...),
					TaskPermissions...),
				PointsPermissions...),
			LevelPermissions...),
		append(
			append(
				append(append(PlanPermissions, RolePermissions...), MenuPermissions...),
				ActionPermissions...,
			),
			MenuVisibilityPermissionPatterns...,
		)...,
	)

	AllPermissionDefinitions = append(
		append(
			append(
				append(
					append(
						append(apiPermissionDefinitions(SystemPermissions), apiPermissionDefinitions(UserPermissions)...),
						apiPermissionDefinitions(GroupPermissions)...),
					apiPermissionDefinitions(TaskPermissions)...),
				apiPermissionDefinitions(PointsPermissions)...),
			apiPermissionDefinitions(LevelPermissions)...),
		append(
			append(
				append(apiPermissionDefinitions(PlanPermissions), append(apiPermissionDefinitions(RolePermissions), apiPermissionDefinitions(MenuPermissions)...)...),
				actionPermissionDefinitions(ActionPermissions)...,
			),
			patternPermissionDefinitions(MenuVisibilityPermissionPatterns, iammw.PermissionTypeMenu)...,
		)...,
	)
)

// apiPermissionDefinitions 处理API权限Definitions。
func apiPermissionDefinitions(permissions []string) []iammw.PermissionDefinition {
	return permissionDefinitions(permissions, iammw.PermissionTypeAPI)
}

// actionPermissionDefinitions 处理action权限Definitions。
func actionPermissionDefinitions(permissions []string) []iammw.PermissionDefinition {
	return permissionDefinitions(permissions, iammw.PermissionTypeAction)
}

// patternPermissionDefinitions 处理pattern权限Definitions。
func patternPermissionDefinitions(permissions []string, permissionType iammw.PermissionType) []iammw.PermissionDefinition {
	return permissionDefinitions(permissions, permissionType)
}

// permissionDefinitions 处理权限Definitions。
func permissionDefinitions(permissions []string, permissionType iammw.PermissionType) []iammw.PermissionDefinition {
	definitions := make([]iammw.PermissionDefinition, 0, len(permissions))
	for _, permission := range permissions {
		definitions = append(definitions, iammw.PermissionDefinition{
			Code: permission,
			Type: permissionType,
		})
	}
	return definitions
}

// 租户相关请求类型

// CreateTenantRequest 定义创建租户请求参数。
type CreateTenantRequest struct {
	Key         string `json:"key" binding:"required,max=64"`
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
}

// UpdateTenantRequest 定义Update租户请求参数。
type UpdateTenantRequest struct {
	Name        string `json:"name" binding:"omitempty,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
}

// 租户状态
const (
	TenantStatusActive   = "active"
	TenantStatusInactive = "inactive"
)
