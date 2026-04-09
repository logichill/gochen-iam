package entity

import (
	"strings"
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/validation"
)

const (
	ScopeTypePlatform = "platform"
	ScopeTypeTenant   = "tenant"

	ScopeStatusActive   = "active"
	ScopeStatusInactive = "inactive"
)

// Scope 授权域节点。
//
// 第一阶段采用 materialized path：
// - `Key` 是稳定路径段；
// - `Path` 使用 `/platform/tenant:acme/` 这种可前缀判定的格式；
// - 平台覆盖租户靠 `HasPrefix(target.Path, ancestor.Path)` 完成。
type Scope struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	Key         string `json:"key" gorm:"size:128;uniqueIndex;not null"`
	Name        string `json:"name" gorm:"size:100;not null"`
	Type        string `json:"type" gorm:"size:32;index;not null"`
	ParentID    *int64 `json:"parent_id,omitempty" gorm:"index"`
	Path        string `json:"path" gorm:"size:1024;uniqueIndex;not null"`
	Depth       int    `json:"depth" gorm:"not null;default:0"`
	Description string `json:"description,omitempty" gorm:"size:500"`
	Status      string `json:"status" gorm:"size:20;default:active"`

	Parent *Scope `json:"parent,omitempty" gorm:"foreignKey:ParentID"`
}

func (Scope) TableName() string {
	return "scopes"
}

func (s *Scope) Validate() error {
	if err := validation.ValidateRequired(s.Key, "scope key"); err != nil {
		return errorx.New(errorx.Validation, "scope key 不能为空")
	}
	if err := validation.ValidateStringLength(s.Key, "scope key", 0, 128); err != nil {
		return errorx.New(errorx.Validation, "scope key 长度不能超过128个字符")
	}
	if err := validation.ValidateRequired(s.Name, "scope name"); err != nil {
		return errorx.New(errorx.Validation, "scope name 不能为空")
	}
	if err := validation.ValidateRequired(s.Type, "scope type"); err != nil {
		return errorx.New(errorx.Validation, "scope type 不能为空")
	}
	if !IsValidScopeType(s.Type) {
		return errorx.New(errorx.Validation, "scope type 无效")
	}
	if err := validation.ValidateRequired(s.Path, "scope path"); err != nil {
		return errorx.New(errorx.Validation, "scope path 不能为空")
	}
	if !strings.HasPrefix(s.Path, "/") || !strings.HasSuffix(s.Path, "/") {
		return errorx.New(errorx.Validation, "scope path 格式无效")
	}
	return nil
}

func (s *Scope) GetEntityType() string {
	return "scope"
}

func (s *Scope) GetID() int64 { return s.ID }

func (s *Scope) SetID(id int64) { s.ID = id }

func (s *Scope) GetCreatedAt() time.Time { return s.CreatedAt }

func (s *Scope) GetUpdatedAt() time.Time { return s.UpdatedAt }

func (s *Scope) SetUpdatedAt(tm time.Time) { s.UpdatedAt = tm }

func (s *Scope) IsDeleted() bool { return s.DeletedAt != nil }

func (s *Scope) MarkAsDeleted() {
	now := time.Now()
	s.DeletedAt = &now
	s.UpdatedAt = now
}

func (s *Scope) Restore() {
	s.DeletedAt = nil
	s.UpdatedAt = time.Now()
}

func (s *Scope) GetDeletedAt() *time.Time { return s.DeletedAt }

func (s *Scope) IsActive() bool {
	return s.Status == "" || s.Status == ScopeStatusActive
}

func (s *Scope) Covers(target *Scope) bool {
	if s == nil || target == nil || s.Path == "" || target.Path == "" {
		return false
	}
	return strings.HasPrefix(target.Path, s.Path)
}

func IsValidScopeType(scopeType string) bool {
	switch strings.TrimSpace(scopeType) {
	case ScopeTypePlatform, ScopeTypeTenant:
		return true
	default:
		return false
	}
}

func ScopePathFor(parentPath, key string) string {
	key = strings.Trim(strings.TrimSpace(key), "/")
	if parentPath == "" || parentPath == "/" {
		return "/" + key + "/"
	}
	return strings.TrimRight(parentPath, "/") + "/" + key + "/"
}
