package entity

import (
	"encoding/json"
	"fmt"
	"time"

	iammw "gochen-iam/middleware"
	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errors"
	"gochen/validation"
)

// PermissionArray 权限数组类型
type PermissionArray []string

// Scan 把当前结果写入目标对象。
func (p *PermissionArray) Scan(value any) error {
	if value == nil {
		*p = PermissionArray{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, p)
	case string:
		return json.Unmarshal([]byte(v), p)
	default:
		return fmt.Errorf("cannot scan %T into PermissionArray", value)
	}
}

// Value 处理值。
func (p PermissionArray) Value() (any, error) {
	if len(p) == 0 {
		return "[]", nil
	}
	return json.Marshal(p)
}

// Role 角色实体
type Role struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	TenantID         string          `json:"tenant_id" gorm:"size:64;not null;index;uniqueIndex:idx_role_name_tenant"`
	OwnerID          string          `json:"owner_id" gorm:"size:128;not null;index"`
	NamespaceScopeID int64           `json:"namespace_scope_id" gorm:"not null;index"`
	Code             string          `json:"code" gorm:"size:50;index"` // 稳定标识，默认与 Name 相同
	Name             string          `json:"name" gorm:"size:50;not null;uniqueIndex:idx_role_name_tenant"`
	Description      string          `json:"description" gorm:"size:500"`
	Permissions      PermissionArray `json:"permissions" gorm:"type:text;serializer:json"`
	IsSystem         bool            `json:"is_system" gorm:"default:false"`
	Status           string          `json:"status" gorm:"size:20;default:active"`

	// 关联关系
	NamespaceScope *Scope  `json:"namespace_scope,omitempty" gorm:"foreignKey:NamespaceScopeID"`
	Users          []User  `json:"users,omitempty" gorm:"many2many:user_role_bindings;"`
	Groups         []Group `json:"groups,omitempty" gorm:"many2many:group_roles;"`
}

// TableName 指定表名
func (Role) TableName() string {
	return "roles"
}

// Validate 验证角色数据
func (r *Role) Validate() error {
	if r.TenantID == "" {
		return errors.NewCode(errors.Validation, "租户ID不能为空")
	}
	if r.OwnerID == "" {
		return errors.NewCode(errors.Validation, "owner_id 不能为空")
	}
	if r.NamespaceScopeID <= 0 {
		return errors.NewCode(errors.Validation, "namespace_scope_id 不能为空")
	}
	if err := validation.ValidateRequired(r.Name, "role name"); err != nil {
		return errors.NewCode(errors.Validation, "角色名称不能为空")
	}
	if err := validation.ValidateStringLength(r.Name, "role name", 0, 50); err != nil {
		return errors.NewCode(errors.Validation, "角色名称不能超过50个字符")
	}
	if err := validation.ValidateStringLength(r.Description, "role description", 0, 500); err != nil {
		return errors.NewCode(errors.Validation, "角色描述不能超过500个字符")
	}
	if r.Status != "" && !isValidRoleStatus(r.Status) {
		return errors.NewCode(errors.Validation, "角色状态无效")
	}
	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (r *Role) GetEntityType() string {
	return "role"
}

// 实现 domain.IEntity 方法
func (r *Role) GetID() int64 { return r.ID }

// SetID 设置ID。
func (r *Role) SetID(id int64) { r.ID = id }

// GetCreatedAt 返回创建At。
func (r *Role) GetCreatedAt() time.Time { return r.CreatedAt }

// GetUpdatedAt 返回更新At。
func (r *Role) GetUpdatedAt() time.Time { return r.UpdatedAt }

// SetUpdatedAt 设置更新At。
func (r *Role) SetUpdatedAt(t time.Time) { r.UpdatedAt = t }

// IsDeleted 判断已删除。
func (r *Role) IsDeleted() bool { return r.DeletedAt != nil }

// MarkAsDeleted 处理MarkAs已删除。
func (r *Role) MarkAsDeleted() { now := time.Now(); r.DeletedAt = &now; r.UpdatedAt = now }

// Restore 恢复数据。
func (r *Role) Restore() { r.DeletedAt = nil; r.UpdatedAt = time.Now() }

// GetDeletedAt 返回已删除At。
func (r *Role) GetDeletedAt() *time.Time { return r.DeletedAt }

// GetTenantID 返回租户ID。
func (r *Role) GetTenantID() string { return r.TenantID }

// SetTenantID 设置租户ID。
func (r *Role) SetTenantID(tenantID string) { r.TenantID = tenantID }

// GetOwnerID 返回资源 owner 标识。
func (r *Role) GetOwnerID() string { return r.OwnerID }

// SetOwnerID 设置资源 owner 标识。
func (r *Role) SetOwnerID(ownerID string) { r.OwnerID = ownerID }

// GetManagedScopeID 返回资源归属的管理 scope。
func (r *Role) GetManagedScopeID() int64 { return r.NamespaceScopeID }

// SetManagedScopeID 设置资源归属的管理 scope。
func (r *Role) SetManagedScopeID(scopeID int64) { r.NamespaceScopeID = scopeID }

// IsActive 检查角色是否激活
func (r *Role) IsActive() bool {
	return r.Status == "active"
}

// IsSystemRole 检查是否为系统角色
func (r *Role) IsSystemRole() bool {
	return r.IsSystem
}

// CanBeDeleted 检查角色是否可以被删除
func (r *Role) CanBeDeleted() bool {
	return !r.IsSystem
}

// HasPermission 检查角色是否拥有指定权限
func (r *Role) HasPermission(permission string) bool {
	for _, perm := range r.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// AddPermission 添加权限
func (r *Role) AddPermission(permission string) {
	if !r.HasPermission(permission) {
		r.Permissions = append(r.Permissions, permission)
		r.SetUpdatedAt(time.Now())
	}
}

// RemovePermission 移除权限
func (r *Role) RemovePermission(permission string) {
	for i, perm := range r.Permissions {
		if perm == permission {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			r.SetUpdatedAt(time.Now())
			break
		}
	}
}

// SetPermissions 设置权限列表
func (r *Role) SetPermissions(permissions []string) {
	r.Permissions = PermissionArray(permissions)
	r.SetUpdatedAt(time.Now())
}

// PermissionCount 获取权限数量
func (r *Role) PermissionCount() int {
	return len(r.Permissions)
}

// Clone 克隆角色（不包含关联关系）
func (r *Role) Clone(newName string) *Role {
	clone := &Role{
		TenantID:         r.TenantID,
		OwnerID:          r.OwnerID,
		NamespaceScopeID: r.NamespaceScopeID,
		Name:             newName,
		Description:      r.Description + " (克隆)",
		Permissions:      make(PermissionArray, len(r.Permissions)),
		IsSystem:         false, // 克隆的角色不是系统角色
		Status:           r.Status,
	}
	copy(clone.Permissions, r.Permissions)
	return clone
}

// Activate 激活角色
func (r *Role) Activate() {
	r.Status = "active"
	r.SetUpdatedAt(time.Now())
}

// Deactivate 停用角色
func (r *Role) Deactivate() {
	if !r.IsSystem {
		r.Status = "inactive"
		r.SetUpdatedAt(time.Now())
	}
}

// UserCount 获取拥有此角色的用户数量
func (r *Role) UserCount() int {
	return len(r.Users)
}

// GroupCount 获取使用此角色作为默认角色的组织数量
func (r *Role) GroupCount() int {
	return len(r.Groups)
}

// HasUsers 检查角色是否被用户使用
func (r *Role) HasUsers() bool {
	return len(r.Users) > 0
}

// HasGroups 检查角色是否被组织使用
func (r *Role) HasGroups() bool {
	return len(r.Groups) > 0
}

// IsInUse 检查角色是否正在使用中
func (r *Role) IsInUse() bool {
	return r.HasUsers() || r.HasGroups()
}

// String 返回字符串表示。
func (r *Role) String() string {
	return fmt.Sprintf("Role{ID: %d, Name: %s, Permissions: %d, IsSystem: %t}",
		r.GetID(), r.Name, len(r.Permissions), r.IsSystem)
}

// 系统预定义角色
var (
	SystemAdminRole = &Role{
		Name:        "system_admin",
		Description: "系统管理员，拥有所有权限",
		Permissions: PermissionArray{
			iammw.PermissionCode("*:*:*").Code,
		},
		IsSystem: true,
		Status:   "active",
	}

	TenantAdminRole = &Role{
		Name:        "admin",
		Description: "租户管理员，拥有租户内管理权限",
		Permissions: PermissionArray{
			iammw.ApiPermission(iammw.ResourceAny, iammw.ActionAny).Code,
			iammw.MenuPermission(iammw.ResourceAny, iammw.ActionView).Code,
		},
		IsSystem: true,
		Status:   "active",
	}

	UserRole = &Role{
		Name:        "user",
		Description: "普通用户角色",
		Permissions: PermissionArray{
			iammw.ApiPermission(iammw.ResourceUser, iammw.ActionSelfRead).Code,
			iammw.ApiPermission(iammw.ResourceUser, iammw.ActionSelfEdit).Code,
		},
		IsSystem: true,
		Status:   "active",
	}
)

// 辅助函数
func isValidRoleStatus(status string) bool {
	validStatuses := []string{"active", "inactive"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}
