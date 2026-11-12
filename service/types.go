package service

import (
	"time"

	iamperm "gochen-iam/permissions"
)

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

// AssignUserRoleBindingRequest 定义用户角色绑定请求。
type AssignUserRoleBindingRequest struct {
	RoleID       int64  `json:"role_id" binding:"required"`
	GrantScopeID *int64 `json:"grant_scope_id,omitempty"`
}

// UserRoleBindingDetail 描述用户在某个 scope 下持有的角色绑定。
type UserRoleBindingDetail struct {
	BindingID          int64    `json:"binding_id"`
	UserID             int64    `json:"user_id"`
	RoleID             int64    `json:"role_id"`
	RoleName           string   `json:"role_name"`
	RoleCode           string   `json:"role_code,omitempty"`
	GrantScopeID       int64    `json:"grant_scope_id"`
	GrantScopeKey      string   `json:"grant_scope_key,omitempty"`
	GrantScopeKind     string   `json:"grant_scope_kind,omitempty"`
	NamespaceScopeID   int64    `json:"namespace_scope_id,omitempty"`
	NamespaceScopeKey  string   `json:"namespace_scope_key,omitempty"`
	NamespaceScopeKind string   `json:"namespace_scope_kind,omitempty"`
	Permissions        []string `json:"permissions,omitempty"`
	Status             string   `json:"status,omitempty"`
}

// ScopeListItem 描述一个授权域节点。
type ScopeListItem struct {
	ID                int64  `json:"id"`
	Key               string `json:"key"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	ParentID          *int64 `json:"parent_id,omitempty"`
	Path              string `json:"path"`
	Depth             int    `json:"depth"`
	Status            string `json:"status"`
	Description       string `json:"description,omitempty"`
	ChildCount        int64  `json:"child_count,omitempty"`
	CanDelete         bool   `json:"can_delete"`
	DeleteBlockReason string `json:"delete_block_reason,omitempty"`
	HealthStatus      string `json:"health_status,omitempty"`
	HealthReason      string `json:"health_reason,omitempty"`
	CanRepair         bool   `json:"can_repair"`
}

// ScopeVisibilityResponse 返回某个 viewer scope 可见的 scope 集合。
type ScopeVisibilityResponse struct {
	ViewerScopeID   int64           `json:"viewer_scope_id"`
	VisibleScopeIDs []int64         `json:"visible_scope_ids"`
	VisibleScopes   []ScopeListItem `json:"visible_scopes"`
}

// CreateScopeRequest 定义创建授权域请求。
type CreateScopeRequest struct {
	Key         string `json:"key" binding:"required,max=128"`
	Name        string `json:"name" binding:"required,max=100"`
	Type        string `json:"type" binding:"required,max=64"`
	ParentID    int64  `json:"parent_id" binding:"required"`
	Description string `json:"description" binding:"omitempty,max=500"`
	Status      string `json:"status" binding:"omitempty,max=20"`
}

// UpdateScopeRequest 定义更新授权域请求。
type UpdateScopeRequest struct {
	Name        string `json:"name" binding:"omitempty,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
	Status      string `json:"status" binding:"omitempty,max=20"`
}

// ScopeGovernanceState 描述某个 scope 在治理台中的删除约束状态。
type ScopeGovernanceState struct {
	ChildCount        int64  `json:"child_count,omitempty"`
	CanDelete         bool   `json:"can_delete"`
	DeleteBlockReason string `json:"delete_block_reason,omitempty"`
	HealthStatus      string `json:"health_status,omitempty"`
	HealthReason      string `json:"health_reason,omitempty"`
	CanRepair         bool   `json:"can_repair"`
}

// TenantGovernanceState 描述某个 tenant 在治理台中的删除约束状态。
type TenantGovernanceState struct {
	CanDelete         bool   `json:"can_delete"`
	DeleteBlockReason string `json:"delete_block_reason,omitempty"`
}

// TenantRootScopeHealth 描述 tenant root scope 的健康状态。
type TenantRootScopeHealth struct {
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	CanRepair bool   `json:"can_repair"`
}

// TenantListItem 描述租户治理列表项。
type TenantListItem struct {
	ID                 int64      `json:"id"`
	Key                string     `json:"key"`
	Name               string     `json:"name"`
	Description        string     `json:"description,omitempty"`
	Status             string     `json:"status,omitempty"`
	RootScopeID        *int64     `json:"root_scope_id,omitempty"`
	CreatedAt          time.Time  `json:"created_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at,omitempty"`
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`
	CanDelete          bool       `json:"can_delete"`
	DeleteBlockReason  string     `json:"delete_block_reason,omitempty"`
	RootScopeStatus    string     `json:"root_scope_status,omitempty"`
	RootScopeReason    string     `json:"root_scope_reason,omitempty"`
	CanRepairRootScope bool       `json:"can_repair_root_scope"`
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

// BulkOperationRequest 批量操作请求
type BulkOperationRequest struct {
	IDs []int64 `json:"ids" binding:"required"`
}

// BulkOperationResponse 批量操作响应
type BulkOperationResponse struct {
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
	SystemPermissionSet = iamperm.NewAPIPermissionSet(iamperm.ResourceSystem, iamperm.ReadWriteDeleteActions()...)
	UserPermissionSet   = iamperm.NewAPIPermissionSet(
		iamperm.ResourceUser,
		iamperm.JoinActions(iamperm.ManageActions(), iamperm.SelfActions())...,
	)
	GroupPermissionSet  = iamperm.NewAPIPermissionSet(iamperm.ResourceGroup, iamperm.ManageActions()...)
	TaskPermissionSet   = iamperm.NewAPIPermissionSet(iamperm.ResourceTask, iamperm.ReadWriteDeleteActions()...)
	PointsPermissionSet = iamperm.NewAPIPermissionSet(iamperm.ResourcePoints, iamperm.ReadWriteActions()...)
	LevelPermissionSet  = iamperm.NewAPIPermissionSet(iamperm.ResourceLevel, iamperm.ReadWriteActions()...)
	PlanPermissionSet   = iamperm.NewAPIPermissionSet(iamperm.ResourcePlan, iamperm.ReadWriteActions()...)
	RolePermissionSet   = iamperm.NewAPIPermissionSet(iamperm.ResourceRole, iamperm.ManageActions()...)
	TenantPermissionSet = iamperm.NewAPIPermissionSet(
		iamperm.ResourceTenant,
		iamperm.JoinActions(iamperm.ManageActions(), []iamperm.Action{iamperm.ActionActivate})...,
	)
	MenuPermissionSet = iamperm.NewAPIPermissionSet(
		iamperm.ResourceMenu,
		iamperm.ActionManage,
		iamperm.ActionRead,
		iamperm.ActionWrite,
		iamperm.ActionPublish,
	)
	ActionPermissionSet         = iamperm.NewActionPermissionSet(iamperm.ResourceMCP, iamperm.ActionInvoke)
	MenuVisibilityPermissionSet = iamperm.NewMenuPermissionSet(iamperm.ResourceAny, iamperm.ActionView)
	APIWildcardPermission       = iamperm.ApiPermission(iamperm.ResourceAny, iamperm.ActionAny)
	AdminEntryPermission        = iamperm.PermissionCode("*:*:*")

	BuiltinWildcardPermissionSpecs = []iamperm.PermissionSpec{
		APIWildcardPermission,
		AdminEntryPermission,
	}

	// 系统权限
	SystemPermissions = SystemPermissionSet.Codes()

	// 用户权限
	UserPermissions = UserPermissionSet.Codes()

	// 组织权限
	GroupPermissions = GroupPermissionSet.Codes()

	// 任务权限
	TaskPermissions = TaskPermissionSet.Codes()

	// 积分权限
	PointsPermissions = PointsPermissionSet.Codes()

	// 等级权限
	LevelPermissions = LevelPermissionSet.Codes()

	// 计划权限
	PlanPermissions = PlanPermissionSet.Codes()

	// 角色权限
	RolePermissions = RolePermissionSet.Codes()

	// 租户权限
	TenantPermissions = TenantPermissionSet.Codes()

	// 菜单权限（后台导航可见性配置）
	MenuPermissions = MenuPermissionSet.Codes()

	// 动作权限（非 HTTP 资源型能力）。
	ActionPermissions = ActionPermissionSet.Codes()

	// 菜单可见性权限是数据驱动的，使用通配定义兜住具体菜单 code。
	MenuVisibilityPermissionPatterns = MenuVisibilityPermissionSet.Codes()

	// 内置角色通配权限只允许系统角色目录持有，不允许自定义角色复用。
	BuiltinWildcardPermissions = iamperm.PermissionCodes(BuiltinWildcardPermissionSpecs...)

	SharedPermissionSpecs = iamperm.JoinPermissionSpecs(
		TaskPermissionSet.Specs(),
		PointsPermissionSet.Specs(),
		LevelPermissionSet.Specs(),
		PlanPermissionSet.Specs(),
		ActionPermissionSet.Specs(),
	)

	IAMPermissionSpecs = iamperm.JoinPermissionSpecs(
		SystemPermissionSet.Specs(),
		UserPermissionSet.Specs(),
		GroupPermissionSet.Specs(),
		RolePermissionSet.Specs(),
		TenantPermissionSet.Specs(),
		MenuPermissionSet.Specs(),
		MenuVisibilityPermissionSet.Specs(),
		BuiltinWildcardPermissionSpecs,
	)

	// IAM 模块自身声明的权限目录。
	IAMPermissions = iamperm.PermissionCodes(IAMPermissionSpecs...)

	IAMPermissionDefinitions = append(
		permissionDefinitions(
			iamperm.JoinPermissionSpecs(
				SystemPermissionSet.Specs(),
				UserPermissionSet.Specs(),
				GroupPermissionSet.Specs(),
				RolePermissionSet.Specs(),
				TenantPermissionSet.Specs(),
				MenuPermissionSet.Specs(),
				MenuVisibilityPermissionSet.Specs(),
			)...,
		),
		builtinWildcardPermissionDefinitions()...,
	)

	AllPermissionSpecs = iamperm.JoinPermissionSpecs(
		IAMPermissionSpecs,
		SharedPermissionSpecs,
	)

	// 所有权限
	AllPermissions = iamperm.PermissionCodes(AllPermissionSpecs...)

	AllPermissionDefinitions = append(
		append([]iamperm.PermissionDefinition(nil), IAMPermissionDefinitions...),
		permissionDefinitions(SharedPermissionSpecs...)...,
	)
)

func permissionDefinitions(specs ...iamperm.PermissionSpec) []iamperm.PermissionDefinition {
	definitions := make([]iamperm.PermissionDefinition, 0, len(specs))
	for _, spec := range specs {
		def := spec.Definition()
		def.Scopes = defaultPermissionScopes(def)
		if defaultPermissionBuiltinOnly(def) {
			def.BuiltinOnly = true
		}
		if def.RiskLevel == "" {
			def.RiskLevel = defaultPermissionRiskLevel(def)
		}
		definitions = append(definitions, def)
	}
	return definitions
}

func builtinWildcardPermissionDefinitions() []iamperm.PermissionDefinition {
	return []iamperm.PermissionDefinition{
		APIWildcardPermission.
			Desc("内置管理员 API 全量权限").
			Scope(iamperm.ScopePlatform, iamperm.ScopeTenant).
			Builtin().
			Definition(),
		AdminEntryPermission.
			Desc("管理员入口").
			Scope(iamperm.ScopePlatform, iamperm.ScopeTenant).
			Builtin().
			Risk(iamperm.RiskLevelCritical).
			Definition(),
	}
}

func defaultPermissionScopes(def iamperm.PermissionDefinition) []string {
	switch def.Resource {
	case string(iamperm.ResourceTenant), string(iamperm.ResourceMenu), string(iamperm.ResourceSystem):
		return []string{string(iamperm.ScopePlatform)}
	default:
		return []string{string(iamperm.ScopePlatform), string(iamperm.ScopeTenant)}
	}
}

func defaultPermissionBuiltinOnly(def iamperm.PermissionDefinition) bool {
	switch def.Code {
	case MenuVisibilityPermissionSet.Code(iamperm.ActionView):
		return true
	default:
		return false
	}
}

func defaultPermissionRiskLevel(def iamperm.PermissionDefinition) string {
	switch def.Code {
	case
		SystemPermissionSet.Code(iamperm.ActionWrite),
		SystemPermissionSet.Code(iamperm.ActionDelete),
		TenantPermissionSet.Code(iamperm.ActionManage),
		TenantPermissionSet.Code(iamperm.ActionWrite),
		TenantPermissionSet.Code(iamperm.ActionDelete),
		TenantPermissionSet.Code(iamperm.ActionActivate),
		ActionPermissionSet.Code(iamperm.ActionInvoke):
		return string(iamperm.RiskLevelCritical)
	case
		UserPermissionSet.Code(iamperm.ActionManage),
		UserPermissionSet.Code(iamperm.ActionWrite),
		UserPermissionSet.Code(iamperm.ActionDelete),
		GroupPermissionSet.Code(iamperm.ActionManage),
		GroupPermissionSet.Code(iamperm.ActionWrite),
		GroupPermissionSet.Code(iamperm.ActionDelete),
		RolePermissionSet.Code(iamperm.ActionManage),
		RolePermissionSet.Code(iamperm.ActionWrite),
		RolePermissionSet.Code(iamperm.ActionDelete),
		MenuPermissionSet.Code(iamperm.ActionWrite),
		MenuPermissionSet.Code(iamperm.ActionPublish),
		TaskPermissionSet.Code(iamperm.ActionWrite),
		PointsPermissionSet.Code(iamperm.ActionWrite),
		LevelPermissionSet.Code(iamperm.ActionWrite),
		PlanPermissionSet.Code(iamperm.ActionWrite):
		return string(iamperm.RiskLevelHigh)
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
