package entity

import "time"

// UserRoleBinding 记录用户在某个 grant scope 下获得的角色绑定。
type UserRoleBinding struct {
	ID           int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID       int64     `json:"user_id" gorm:"not null;index;uniqueIndex:idx_user_role_grant_scope"`
	RoleID       int64     `json:"role_id" gorm:"not null;index;uniqueIndex:idx_user_role_grant_scope"`
	GrantScopeID int64     `json:"grant_scope_id" gorm:"not null;index;uniqueIndex:idx_user_role_grant_scope"`
	Status       string    `json:"status" gorm:"size:20;not null;default:active;index"`
	CreatedAt    time.Time `json:"created_at" gorm:"not null;autoCreateTime"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"not null;autoUpdateTime"`
}

// TableName 指定表名。
func (UserRoleBinding) TableName() string {
	return "user_role_bindings"
}
