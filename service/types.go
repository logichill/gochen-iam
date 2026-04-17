package service

import iammw "gochen-iam/middleware"

// 用户相关请求和响应类型

// RegisterRequest 用户注册请求
//
// 注意：TenantID 不再从请求体获取，而是从上下文中提取（由 middleware 注入），
// 以防止客户端伪造租户 ID 导致跨租户写入。
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

// AuthScopeOption 描述一次认证后可选择进入的 active scope。
type AuthScopeOption struct {
	ScopeID     int64    `json:"scope_id"`
	ScopeKey    string   `json:"scope_key"`
	ScopeKind   string   `json:"scope_kind"`
	BindingIDs  []int64  `json:"binding_ids,omitempty"`
	RoleNames   []string `json:"role_names,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// AuthenticateResult 用户认证结果（第一阶段，不包含 access token）。
type AuthenticateResult struct {
	UserID          int64             `json:"user_id"`
	Username        string            `json:"username"`
	Email           string            `json:"email"`
	BindingVersion  string            `json:"binding_version"`
	AvailableScopes []AuthScopeOption `json:"available_scopes"`
}

// ActivateScopeRequest 进入某个显式选择的 active scope。
type ActivateScopeRequest struct {
	ScopeID int64 `json:"scope_id" binding:"required"`
}

// ActiveScopeSession 表达进入工作态后签发 access token 所需的最小快照。
type ActiveScopeSession struct {
	UserID         int64    `json:"user_id"`
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	ActiveScopeID  int64    `json:"active_scope_id"`
	BindingVersion string   `json:"binding_version"`
	RoleNames      []string `json:"role_names,omitempty"`
	Permissions    []string `json:"permissions"`
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
	TenantID    string `json:"tenant_id" binding:"omitempty,max=64"`
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
	ParentID    *int64 `json:"parent_id" binding:"omitempty"`
}

// UpdateGroupRequest 更新组织请求。
//
// 说明：
// - 普通字段继续使用常规 DTO；
// - 需要“字段出现语义”的特殊字段（如 parent_id）应通过 `FieldPatch` 传入 service。
type UpdateGroupRequest struct {
	Name        string `json:"name" binding:"omitempty,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
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
	TenantID    string   `json:"tenant_id" binding:"omitempty,max=64"`
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
	AdminRoleName       = "admin"
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
		"api:user:manage",
		"api:user:read",
		"api:user:write",
		"api:user:delete",
		"api:user:read_self",
		"api:user:update_self",
	}

	// 组织权限
	GroupPermissions = []string{
		"api:group:manage",
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
		"api:role:manage",
		"api:role:read",
		"api:role:write",
		"api:role:delete",
	}

	// 租户权限
	TenantPermissions = []string{
		"api:tenant:manage",
		"api:tenant:read",
		"api:tenant:write",
		"api:tenant:delete",
		"api:tenant:activate",
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

	// 内置角色通配权限只允许系统角色目录持有，不允许自定义角色复用。
	BuiltinWildcardPermissions = []string{
		"api:*:*",
		"*:*:*",
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
				append(append(append(PlanPermissions, RolePermissions...), TenantPermissions...), MenuPermissions...),
				ActionPermissions...,
			),
			append(MenuVisibilityPermissionPatterns, BuiltinWildcardPermissions...)...,
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
				append(apiPermissionDefinitions(PlanPermissions), append(append(apiPermissionDefinitions(RolePermissions), apiPermissionDefinitions(TenantPermissions)...), apiPermissionDefinitions(MenuPermissions)...)...),
				actionPermissionDefinitions(ActionPermissions)...,
			),
			append(
				patternPermissionDefinitions(MenuVisibilityPermissionPatterns, iammw.PermissionTypeMenu),
				builtinWildcardPermissionDefinitions()...,
			)...,
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
		spec := iammw.PermissionCode(permission).Definition()
		spec.Type = permissionType
		spec.Scopes = defaultPermissionScopes(spec)
		spec.BuiltinOnly = defaultPermissionBuiltinOnly(spec)
		spec.RiskLevel = defaultPermissionRiskLevel(spec)
		definitions = append(definitions, spec)
	}
	return definitions
}

func builtinWildcardPermissionDefinitions() []iammw.PermissionDefinition {
	return []iammw.PermissionDefinition{
		iammw.PermissionCode("api:*:*").
			Desc("内置管理员 API 全量权限").
			Scope(iammw.ScopePlatform, iammw.ScopeTenant).
			Builtin().
			Definition(),
		iammw.PermissionCode("*:*:*").
			Desc("管理员入口").
			Scope(iammw.ScopePlatform, iammw.ScopeTenant).
			Builtin().
			Risk(iammw.RiskLevelCritical).
			Definition(),
	}
}

func defaultPermissionScopes(def iammw.PermissionDefinition) []string {
	switch def.Resource {
	case string(iammw.ResourceTenant), string(iammw.ResourceMenu), string(iammw.ResourceSystem):
		return []string{string(iammw.ScopePlatform)}
	default:
		return []string{string(iammw.ScopePlatform), string(iammw.ScopeTenant)}
	}
}

func defaultPermissionBuiltinOnly(def iammw.PermissionDefinition) bool {
	switch def.Code {
	case "menu:*:view":
		return true
	default:
		return false
	}
}

func defaultPermissionRiskLevel(def iammw.PermissionDefinition) string {
	switch def.Code {
	case
		"api:system:write",
		"api:system:delete",
		"api:tenant:manage",
		"api:tenant:write",
		"api:tenant:delete",
		"api:tenant:activate",
		"action:mcp:invoke":
		return string(iammw.RiskLevelCritical)
	case
		"api:user:manage",
		"api:user:write",
		"api:user:delete",
		"api:group:manage",
		"api:group:write",
		"api:group:delete",
		"api:role:manage",
		"api:role:write",
		"api:role:delete",
		"api:menu:write",
		"api:menu:publish",
		"api:task:write",
		"api:points:write",
		"api:level:write",
		"api:plan:write":
		return string(iammw.RiskLevelHigh)
	default:
		return ""
	}
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
