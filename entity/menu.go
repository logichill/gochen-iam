package entity

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/runtime/errorx"
)

// StringArray 字符串数组类型（用于 JSON 序列化到 DB text 字段）。
type StringArray []string

func (a *StringArray) Scan(value any) error {
	if value == nil {
		*a = StringArray{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, a)
	case string:
		return json.Unmarshal([]byte(v), a)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}

func (a StringArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

const (
	MenuTypeGroup = "group"
	MenuTypePage  = "page"
	MenuTypeLink  = "link"
)

// MenuItem 后台菜单项（全局定义）。
//
// 设计要点：
// - 菜单不作为安全边界；安全边界仍由 API 权限校验保证；
// - 菜单项可绑定 any/all 权限条件，用于导航可见性过滤；
type MenuItem struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	Code     string `json:"code" gorm:"size:100;uniqueIndex;not null"`
	ParentID *int64 `json:"parent_id,omitempty" gorm:"index"`

	Title string `json:"title" gorm:"size:200;not null"`
	Path  string `json:"path,omitempty" gorm:"size:500"`
	Icon  string `json:"icon,omitempty" gorm:"size:200"`

	Type  string `json:"type" gorm:"size:20;default:page"`
	Order int    `json:"order" gorm:"default:0"`

	// 前端路由/组件元数据（可选）
	Route     string `json:"route,omitempty" gorm:"size:500"`
	Component string `json:"component,omitempty" gorm:"size:500"`

	// 可见性与发布状态
	Hidden    bool `json:"hidden" gorm:"default:false"`
	Disabled  bool `json:"disabled" gorm:"default:false"`
	Published bool `json:"published" gorm:"default:false"`

	AnyOfPermissions StringArray `json:"any_of_permissions,omitempty" gorm:"type:text;serializer:json"`
	AllOfPermissions StringArray `json:"all_of_permissions,omitempty" gorm:"type:text;serializer:json"`
}

func (MenuItem) TableName() string { return "menu_items" }

func (m *MenuItem) Validate() error {
	if m.Code == "" {
		return errorx.NewError(errorx.Validation, "menu code is required")
	}
	if len(m.Code) > 100 {
		return errorx.NewError(errorx.Validation, "menu code is too long")
	}
	if m.Title == "" {
		return errorx.NewError(errorx.Validation, "menu title is required")
	}
	if len(m.Title) > 200 {
		return errorx.NewError(errorx.Validation, "menu title is too long")
	}
	if m.Type == "" {
		m.Type = MenuTypePage
	}
	switch m.Type {
	case MenuTypeGroup, MenuTypePage, MenuTypeLink:
	default:
		return errorx.NewError(errorx.Validation, "menu type is invalid")
	}
	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (m *MenuItem) GetEntityType() string {
	return "menu_item"
}

// 兼容 domain.IEntity 方法
func (m *MenuItem) GetID() int64             { return m.ID }
func (m *MenuItem) SetID(id int64)           { m.ID = id }
func (m *MenuItem) GetCreatedAt() time.Time  { return m.CreatedAt }
func (m *MenuItem) GetUpdatedAt() time.Time  { return m.UpdatedAt }
func (m *MenuItem) SetUpdatedAt(t time.Time) { m.UpdatedAt = t }
func (m *MenuItem) IsDeleted() bool          { return m.DeletedAt != nil }
func (m *MenuItem) MarkAsDeleted()           { now := time.Now(); m.DeletedAt = &now; m.UpdatedAt = now }
func (m *MenuItem) Restore()                 { m.DeletedAt = nil; m.UpdatedAt = time.Now() }
func (m *MenuItem) GetDeletedAt() *time.Time { return m.DeletedAt }
