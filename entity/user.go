package entity

import (
	"regexp"
	"time"

	sharedentity "gochen/domain/entity"
	"gochen/errors"
)

// User 用户实体
type User struct {
	sharedentity.EntityFields
	Username    string     `json:"username" gorm:"uniqueIndex;size:50;not null"`
	Email       string     `json:"email" gorm:"uniqueIndex;size:100;not null"`
	Password    string     `json:"password" gorm:"column:password_hash;size:255;not null"`
	Status      string     `json:"status" gorm:"size:20;default:active"`
	Avatar      string     `json:"avatar" gorm:"size:500"`
	LastLoginAt *time.Time `json:"last_login_at"`

	// 关联关系
	Groups []Group `json:"groups" gorm:"many2many:user_groups;"`
	Roles  []Role  `json:"roles" gorm:"many2many:user_roles;"`
}

// TableName 指定表名
func (*User) TableName() string {
	return "users"
}

// Validate 验证用户数据（指针接收者）
func (u *User) Validate() error {
	if u.Username == "" {
		return errors.NewError(errors.ErrCodeValidation, "用户名不能为空")
	}
	if len(u.Username) < 3 || len(u.Username) > 50 {
		return errors.NewError(errors.ErrCodeValidation, "用户名长度必须在3-50个字符之间")
	}

	if u.Email == "" {
		return errors.NewError(errors.ErrCodeValidation, "邮箱不能为空")
	}
	if !isValidEmail(u.Email) {
		return errors.NewError(errors.ErrCodeValidation, "邮箱格式不正确")
	}

	if u.Password == "" {
		return errors.NewError(errors.ErrCodeValidation, "密码不能为空")
	}
	if len(u.Password) < 6 {
		return errors.NewError(errors.ErrCodeValidation, "密码长度不能少于6个字符")
	}

	if u.Status != "" && !isValidUserStatus(u.Status) {
		return errors.NewError(errors.ErrCodeValidation, "用户状态无效")
	}

	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (u *User) GetEntityType() string {
	return "user"
}

// 兼容 domain.IEntity 方法
func (u *User) GetID() int64             { return u.ID }
func (u *User) SetID(id int64)           { u.ID = id }
func (u *User) GetCreatedAt() time.Time  { return u.CreatedAt }
func (u *User) GetUpdatedAt() time.Time  { return u.UpdatedAt }
func (u *User) SetUpdatedAt(t time.Time) { u.UpdatedAt = t }
func (u *User) IsDeleted() bool          { return u.DeletedAt != nil }
func (u *User) MarkAsDeleted()           { now := time.Now(); u.DeletedAt = &now; u.UpdatedAt = now }
func (u *User) Restore()                 { u.DeletedAt = nil; u.UpdatedAt = time.Now() }
func (u *User) GetDeletedAt() *time.Time { return u.DeletedAt }

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

// GetAllPermissions 获取用户所有权限
func (u *User) GetAllPermissions() []string {
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

// 辅助函数
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func isValidUserStatus(status string) bool {
	validStatuses := []string{"active", "inactive", "locked", "pending"}
	for _, validStatus := range validStatuses {
		if status == validStatus {
			return true
		}
	}
	return false
}
