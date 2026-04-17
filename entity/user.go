package entity

import (
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/validation"
)

// User 用户实体
type User struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	TenantID       string     `json:"tenant_id" gorm:"size:64;not null;index;uniqueIndex:idx_user_username_tenant;uniqueIndex:idx_user_email_tenant"`
	HomeTenantID   string     `json:"home_tenant_id" gorm:"size:64;not null;index"`
	HomeScopeID    int64      `json:"home_scope_id" gorm:"not null;index"`
	ManagedScopeID int64      `json:"managed_scope_id" gorm:"not null;index"`
	OwnerID        string     `json:"owner_id" gorm:"size:128;not null;index"`
	Username       string     `json:"username" gorm:"size:50;not null;uniqueIndex:idx_user_username_tenant"`
	Email          string     `json:"email" gorm:"size:100;not null;uniqueIndex:idx_user_email_tenant"`
	Password       string     `json:"password" gorm:"column:password_hash;size:255;not null"`
	Status         string     `json:"status" gorm:"size:20;default:active"`
	Avatar         string     `json:"avatar" gorm:"size:500"`
	LastLoginAt    *time.Time `json:"last_login_at"`

	// 关联关系
	Groups []Group `json:"groups" gorm:"many2many:user_groups;"`
	Roles  []Role  `json:"roles" gorm:"many2many:user_role_bindings;"`
}

// TableName 指定表名
func (*User) TableName() string {
	return "users"
}

// Validate 验证用户数据（指针接收者）
func (u *User) Validate() error {
	if err := validation.ValidateRequired(u.TenantID, "tenant_id"); err != nil {
		return errorx.New(errorx.Validation, "租户ID不能为空")
	}
	if err := validation.ValidateRequired(u.HomeTenantID, "home_tenant_id"); err != nil {
		return errorx.New(errorx.Validation, "home_tenant_id 不能为空")
	}
	if u.HomeScopeID <= 0 {
		return errorx.New(errorx.Validation, "home_scope_id 不能为空")
	}
	if u.ManagedScopeID <= 0 {
		return errorx.New(errorx.Validation, "managed_scope_id 不能为空")
	}
	if err := validation.ValidateRequired(u.OwnerID, "owner_id"); err != nil {
		return errorx.New(errorx.Validation, "owner_id 不能为空")
	}
	if err := validation.ValidateRequired(u.Username, "username"); err != nil {
		return errorx.New(errorx.Validation, "用户名不能为空")
	}
	if err := validation.ValidateStringLength(u.Username, "username", 3, 50); err != nil {
		return errorx.New(errorx.Validation, "用户名长度必须在3-50个字符之间")
	}

	if err := validation.ValidateRequired(u.Email, "email"); err != nil {
		return errorx.New(errorx.Validation, "邮箱不能为空")
	}
	if err := validation.ValidateEmail(u.Email); err != nil {
		return errorx.New(errorx.Validation, "邮箱格式不正确")
	}

	if err := validation.ValidateRequired(u.Password, "password"); err != nil {
		return errorx.New(errorx.Validation, "密码不能为空")
	}
	if err := validation.ValidateStringLength(u.Password, "password", 6, 0); err != nil {
		return errorx.New(errorx.Validation, "密码长度不能少于6个字符")
	}

	if u.Status != "" && !isValidUserStatus(u.Status) {
		return errorx.New(errorx.Validation, "用户状态无效")
	}

	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (u *User) GetEntityType() string {
	return "user"
}

// 实现 domain.IEntity 方法
func (u *User) GetID() int64 { return u.ID }

// SetID 设置ID。
func (u *User) SetID(id int64) { u.ID = id }

// GetCreatedAt 返回创建At。
func (u *User) GetCreatedAt() time.Time { return u.CreatedAt }

// GetUpdatedAt 返回更新At。
func (u *User) GetUpdatedAt() time.Time { return u.UpdatedAt }

// SetUpdatedAt 设置更新At。
func (u *User) SetUpdatedAt(t time.Time) { u.UpdatedAt = t }

// IsDeleted 判断已删除。
func (u *User) IsDeleted() bool { return u.DeletedAt != nil }

// MarkAsDeleted 处理MarkAs已删除。
func (u *User) MarkAsDeleted() { now := time.Now(); u.DeletedAt = &now; u.UpdatedAt = now }

// Restore 恢复数据。
func (u *User) Restore() { u.DeletedAt = nil; u.UpdatedAt = time.Now() }

// GetDeletedAt 返回已删除At。
func (u *User) GetDeletedAt() *time.Time { return u.DeletedAt }

// GetTenantID 返回租户ID。
func (u *User) GetTenantID() string { return u.TenantID }

// SetTenantID 设置租户ID。
func (u *User) SetTenantID(tenantID string) { u.TenantID = tenantID }

// GetHomeTenantID 返回主体归属租户。
func (u *User) GetHomeTenantID() string { return u.HomeTenantID }

// SetHomeTenantID 设置主体归属租户。
func (u *User) SetHomeTenantID(tenantID string) { u.HomeTenantID = tenantID }

// GetHomeScopeID 返回主体默认归属 scope。
func (u *User) GetHomeScopeID() int64 { return u.HomeScopeID }

// SetHomeScopeID 设置主体默认归属 scope。
func (u *User) SetHomeScopeID(scopeID int64) { u.HomeScopeID = scopeID }

// GetManagedScopeID 返回资源归属的管理 scope。
func (u *User) GetManagedScopeID() int64 { return u.ManagedScopeID }

// SetManagedScopeID 设置资源归属的管理 scope。
func (u *User) SetManagedScopeID(scopeID int64) { u.ManagedScopeID = scopeID }

// GetOwnerID 返回资源 owner 标识。
func (u *User) GetOwnerID() string { return u.OwnerID }

// SetOwnerID 设置资源 owner 标识。
func (u *User) SetOwnerID(ownerID string) { u.OwnerID = ownerID }

// IsActive 检查用户是否激活
func (u *User) IsActive() bool {
	return u.Status == "active"
}

// IsLocked 检查用户是否被锁定
func (u *User) IsLocked() bool {
	return u.Status == "locked"
}

// Activate 激活用户
func (u *User) Activate() {
	u.Status = "active"
	u.SetUpdatedAt(time.Now())
}

// Lock 锁定用户
func (u *User) Lock() {
	u.Status = "locked"
	u.SetUpdatedAt(time.Now())
}

// Deactivate 停用用户
func (u *User) Deactivate() {
	u.Status = "inactive"
	u.SetUpdatedAt(time.Now())
}

// Unlock 解锁用户（恢复为激活状态）
func (u *User) Unlock() {
	u.Status = "active"
	u.SetUpdatedAt(time.Now())
}

// UpdateLastLogin 更新最后登录时间
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.SetUpdatedAt(now)
}

// HasRole 检查用户是否拥有指定角色
func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// HasPermission 检查用户是否拥有指定权限
func (u *User) HasPermission(permission string) bool {
	for _, role := range u.Roles {
		if role.HasPermission(permission) {
			return true
		}
	}
	return false
}

// AllPermissions 获取用户所有权限
func (u *User) AllPermissions() []string {
	permissionSet := make(map[string]bool)
	var permissions []string

	for _, role := range u.Roles {
		for _, perm := range role.Permissions {
			if !permissionSet[perm] {
				permissionSet[perm] = true
				permissions = append(permissions, perm)
			}
		}
	}

	return permissions
}

// isValidUserStatus 判断有效用户状态。
func isValidUserStatus(status string) bool {
	validStatuses := []string{"active", "inactive", "locked", "pending"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}
