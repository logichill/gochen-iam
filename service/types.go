package service

import (
	"time"
)

// 用户相关请求和响应类型

// RegisterRequest 用户注册请求
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// LoginRequest 用户登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse 用户登录响应
type LoginResponse struct {
	UserID      int64     `json:"user_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Permissions []string  `json:"permissions"`
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

// CreateRoleRequest 创建角色请求
type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required,max=50"`
	Description string   `json:"description" binding:"omitempty,max=500"`
	Permissions []string `json:"permissions" binding:"required"`
}

// UpdateRoleRequest 更新角色请求
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
		"system:read",
		"system:write",
		"system:delete",
	}

	// 用户权限
	UserPermissions = []string{
		"user:read",
		"user:write",
		"user:delete",
		"user:read_self",
		"user:update_self",
	}

	// 组织权限
	GroupPermissions = []string{
		"group:read",
		"group:write",
		"group:delete",
	}

	// 任务权限
	TaskPermissions = []string{
		"task:read",
		"task:write",
		"task:delete",
	}

	// 积分权限
	PointsPermissions = []string{
		"points:read",
		"points:write",
	}

	// 等级权限
	LevelPermissions = []string{
		"level:read",
		"level:write",
	}

	// 计划权限
	PlanPermissions = []string{
		"plan:read",
		"plan:write",
	}

	// 角色权限
	RolePermissions = []string{
		"role:read",
		"role:write",
		"role:delete",
	}

	// 菜单权限（后台导航可见性配置）
	MenuPermissions = []string{
		"menu:read",
		"menu:write",
		"menu:publish",
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
		append(append(PlanPermissions, RolePermissions...), MenuPermissions...)...,
	)
)

// 租户相关请求类型

// CreateTenantRequest 创建租户请求
type CreateTenantRequest struct {
	Key         string `json:"key" binding:"required,max=64"`
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
}

// UpdateTenantRequest 更新租户请求
type UpdateTenantRequest struct {
	Name        string `json:"name" binding:"omitempty,max=100"`
	Description string `json:"description" binding:"omitempty,max=500"`
}

// 租户状态
const (
	TenantStatusActive   = "active"
	TenantStatusInactive = "inactive"
)
