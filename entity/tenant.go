package entity

import (
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/validation"
)

// Tenant 租户实体（普通审计型聚合，不使用 Event Sourcing）
type Tenant struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	Key         string `json:"key" gorm:"uniqueIndex;size:64;not null"` // 业务主键
	Name        string `json:"name" gorm:"size:100;not null"`           // 租户名称
	Description string `json:"description" gorm:"size:500"`             // 描述
	Status      string `json:"status" gorm:"size:20;default:inactive"`  // 状态：active/inactive
}

// TableName 指定表名
func (Tenant) TableName() string {
	return "tenants"
}

// Validate 校验租户数据
func (t *Tenant) Validate() error {
	if err := validation.ValidateRequired(t.Key, "tenant key"); err != nil {
		return errorx.New(errorx.Validation, "租户编码不能为空")
	}
	if err := validation.ValidateStringLength(t.Key, "tenant key", 0, 64); err != nil {
		return errorx.New(errorx.Validation, "租户编码长度不能超过64个字符")
	}
	if err := validation.ValidateRequired(t.Name, "tenant name"); err != nil {
		return errorx.New(errorx.Validation, "租户名称不能为空")
	}
	if err := validation.ValidateStringLength(t.Name, "tenant name", 0, 100); err != nil {
		return errorx.New(errorx.Validation, "租户名称不能超过100个字符")
	}
	if err := validation.ValidateStringLength(t.Description, "tenant description", 0, 500); err != nil {
		return errorx.New(errorx.Validation, "租户描述不能超过500个字符")
	}
	return nil
}

// GetEntityType 获取实体类型
func (t *Tenant) GetEntityType() string {
	return "tenant"
}

// 兼容 domain.IEntity 方法
func (t *Tenant) GetID() int64              { return t.ID }
func (t *Tenant) SetID(id int64)            { t.ID = id }
func (t *Tenant) GetCreatedAt() time.Time   { return t.CreatedAt }
func (t *Tenant) GetUpdatedAt() time.Time   { return t.UpdatedAt }
func (t *Tenant) SetUpdatedAt(tm time.Time) { t.UpdatedAt = tm }
func (t *Tenant) IsDeleted() bool           { return t.DeletedAt != nil }
func (t *Tenant) MarkAsDeleted()            { now := time.Now(); t.DeletedAt = &now; t.UpdatedAt = now }
func (t *Tenant) Restore()                  { t.DeletedAt = nil; t.UpdatedAt = time.Now() }
func (t *Tenant) GetDeletedAt() *time.Time  { return t.DeletedAt }

// IsActive 是否处于启用状态
func (t *Tenant) IsActive() bool {
	return t.Status == "active"
}

// Activate 启用租户
func (t *Tenant) Activate() {
	t.Status = "active"
	t.SetUpdatedAt(time.Now())
}

// Deactivate 禁用租户
func (t *Tenant) Deactivate() {
	t.Status = "inactive"
	t.SetUpdatedAt(time.Now())
}
