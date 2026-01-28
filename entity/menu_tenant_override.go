package entity

import (
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/runtime/errorx"
)

// MenuTenantOverride 菜单项的租户级覆盖配置。
//
// 约定：
// - tenant_id 由 HTTP Header X-Tenant-ID 注入到请求上下文；
// - MenuCode 作为稳定标识，用于关联全局 MenuItem（避免依赖自增 ID）。
type MenuTenantOverride struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	TenantID string `json:"tenant_id" gorm:"size:64;not null;uniqueIndex:uidx_tenant_menu_code,priority:1"`
	MenuCode string `json:"menu_code" gorm:"size:100;not null;uniqueIndex:uidx_tenant_menu_code,priority:2"`

	Title     *string `json:"title,omitempty" gorm:"size:200"`
	Path      *string `json:"path,omitempty" gorm:"size:500"`
	Icon      *string `json:"icon,omitempty" gorm:"size:200"`
	Route     *string `json:"route,omitempty" gorm:"size:500"`
	Component *string `json:"component,omitempty" gorm:"size:500"`
	Order     *int    `json:"order,omitempty"`

	// 覆盖可见性（为 true 时表示强制隐藏/禁用；nil 表示不覆盖）。
	Hidden   *bool `json:"hidden,omitempty"`
	Disabled *bool `json:"disabled,omitempty"`
}

func (MenuTenantOverride) TableName() string { return "menu_tenant_overrides" }

func (o *MenuTenantOverride) Validate() error {
	if o.TenantID == "" {
		return errorx.NewError(errorx.Validation, "tenant_id is required")
	}
	if len(o.TenantID) > 64 {
		return errorx.NewError(errorx.Validation, "tenant_id is too long")
	}
	if o.MenuCode == "" {
		return errorx.NewError(errorx.Validation, "menu_code is required")
	}
	if len(o.MenuCode) > 100 {
		return errorx.NewError(errorx.Validation, "menu_code is too long")
	}
	if o.Title != nil && len(*o.Title) > 200 {
		return errorx.NewError(errorx.Validation, "menu title is too long")
	}
	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (o *MenuTenantOverride) GetEntityType() string {
	return "menu_tenant_override"
}

// 兼容 domain.IEntity 方法
func (o *MenuTenantOverride) GetID() int64             { return o.ID }
func (o *MenuTenantOverride) SetID(id int64)           { o.ID = id }
func (o *MenuTenantOverride) GetCreatedAt() time.Time  { return o.CreatedAt }
func (o *MenuTenantOverride) GetUpdatedAt() time.Time  { return o.UpdatedAt }
func (o *MenuTenantOverride) SetUpdatedAt(t time.Time) { o.UpdatedAt = t }
func (o *MenuTenantOverride) IsDeleted() bool          { return o.DeletedAt != nil }
func (o *MenuTenantOverride) MarkAsDeleted() {
	now := time.Now()
	o.DeletedAt = &now
	o.UpdatedAt = now
}
func (o *MenuTenantOverride) Restore()                 { o.DeletedAt = nil; o.UpdatedAt = time.Now() }
func (o *MenuTenantOverride) GetDeletedAt() *time.Time { return o.DeletedAt }
