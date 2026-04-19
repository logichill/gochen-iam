package entity

import (
	"strings"
	"time"
	"unicode"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errors"
	"gochen/validate"
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
	if err := validate.Required(s.Key, "scope key"); err != nil {
		return errors.NewCode(errors.Validation, "scope key 不能为空")
	}
	if err := validate.StringLength(s.Key, "scope key", 0, 128); err != nil {
		return errors.NewCode(errors.Validation, "scope key 长度不能超过128个字符")
	}
	if !isValidScopeSegment(s.Key) {
		return errors.NewCode(errors.Validation, "scope key 格式无效")
	}
	if err := validate.Required(s.Name, "scope name"); err != nil {
		return errors.NewCode(errors.Validation, "scope name 不能为空")
	}
	if err := validate.Required(s.Type, "scope type"); err != nil {
		return errors.NewCode(errors.Validation, "scope type 不能为空")
	}
	if !IsValidScopeType(s.Type) {
		return errors.NewCode(errors.Validation, "scope type 无效")
	}
	if err := validate.Required(s.Path, "scope path"); err != nil {
		return errors.NewCode(errors.Validation, "scope path 不能为空")
	}
	if !strings.HasPrefix(s.Path, "/") || !strings.HasSuffix(s.Path, "/") {
		return errors.NewCode(errors.Validation, "scope path 格式无效")
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
	return isValidScopeSegment(scopeType)
}

func ScopePathFor(parentPath, key string) string {
	key = strings.Trim(strings.TrimSpace(key), "/")
	if parentPath == "" || parentPath == "/" {
		return "/" + key + "/"
	}
	return strings.TrimRight(parentPath, "/") + "/" + key + "/"
}

func isValidScopeSegment(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case ':', '-', '_', '.':
			continue
		default:
			return false
		}
	}
	return !strings.Contains(value, "/")
}
