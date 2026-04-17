package entity

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gochen/domain"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/validation"
)

// Group 组织实体
type Group struct {
	crud.Entity[int64]
	domain.Timestamps
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	TenantID       string `json:"tenant_id" gorm:"size:64;not null;index;uniqueIndex:idx_group_name_parent_tenant"`
	ManagedScopeID int64  `json:"managed_scope_id" gorm:"not null;index"`
	OwnerID        string `json:"owner_id" gorm:"size:128;not null;index"`
	Name           string `json:"name" gorm:"size:100;not null;uniqueIndex:idx_group_name_parent_tenant"`
	// Code 用于承接管理端当前仍会回传的组织编码字段；当前 groups 表未持久化该列。
	Code        string `json:"code,omitempty" gorm:"-"`
	Description string `json:"description" gorm:"size:500"`
	ParentID    *int64 `json:"parent_id" gorm:"index"`
	ParentKey   int64  `json:"-" gorm:"not null;default:0;index;uniqueIndex:idx_group_name_parent_tenant"`
	Level       int    `json:"level" gorm:"default:1"`
	Path        string `json:"path" gorm:"size:500"` // 层级路径，如: /1/2/3

	// 关联关系
	Parent       *Group   `json:"parent,omitempty" gorm:"foreignKey:ParentID"`
	Children     []*Group `json:"children,omitempty" gorm:"foreignKey:ParentID"`
	Users        []*User  `json:"users,omitempty" gorm:"many2many:user_groups;"`
	DefaultRoles []*Role  `json:"default_roles,omitempty" gorm:"many2many:group_roles;"`
}

// TableName 指定表名
func (Group) TableName() string {
	return "groups"
}

// Validate 验证组织数据
func (g *Group) Validate() error {
	if g.TenantID == "" {
		return errorx.New(errorx.Validation, "租户ID不能为空")
	}
	if g.ManagedScopeID <= 0 {
		return errorx.New(errorx.Validation, "managed_scope_id 不能为空")
	}
	if g.OwnerID == "" {
		return errorx.New(errorx.Validation, "owner_id 不能为空")
	}
	if err := validation.ValidateRequired(g.Name, "group name"); err != nil {
		return errorx.New(errorx.Validation, "组织名称不能为空")
	}
	if err := validation.ValidateStringLength(g.Name, "group name", 0, 100); err != nil {
		return errorx.New(errorx.Validation, "组织名称不能超过100个字符")
	}
	if err := validation.ValidateStringLength(g.Description, "group description", 0, 500); err != nil {
		return errorx.New(errorx.Validation, "组织描述不能超过500个字符")
	}
	return nil
}

// GetEntityType 获取实体类型（值接收者）
func (g *Group) GetEntityType() string {
	return "group"
}

// 实现 domain.IEntity 方法
func (g *Group) GetID() int64 { return g.ID }

// SetID 设置ID。
func (g *Group) SetID(id int64) { g.ID = id }

// GetCreatedAt 返回创建At。
func (g *Group) GetCreatedAt() time.Time { return g.CreatedAt }

// GetUpdatedAt 返回更新At。
func (g *Group) GetUpdatedAt() time.Time { return g.UpdatedAt }

// SetUpdatedAt 设置更新At。
func (g *Group) SetUpdatedAt(t time.Time) { g.UpdatedAt = t }

// IsDeleted 判断已删除。
func (g *Group) IsDeleted() bool { return g.DeletedAt != nil }

// MarkAsDeleted 处理MarkAs已删除。
func (g *Group) MarkAsDeleted() { now := time.Now(); g.DeletedAt = &now; g.UpdatedAt = now }

// Restore 恢复数据。
func (g *Group) Restore() { g.DeletedAt = nil; g.UpdatedAt = time.Now() }

// GetDeletedAt 返回已删除At。
func (g *Group) GetDeletedAt() *time.Time { return g.DeletedAt }

// GetTenantID 返回租户ID。
func (g *Group) GetTenantID() string { return g.TenantID }

// SetTenantID 设置租户ID。
func (g *Group) SetTenantID(tenantID string) { g.TenantID = tenantID }

// GetManagedScopeID 返回资源归属的管理 scope。
func (g *Group) GetManagedScopeID() int64 { return g.ManagedScopeID }

// SetManagedScopeID 设置资源归属的管理 scope。
func (g *Group) SetManagedScopeID(scopeID int64) { g.ManagedScopeID = scopeID }

// GetOwnerID 返回资源 owner 标识。
func (g *Group) GetOwnerID() string { return g.OwnerID }

// SetOwnerID 设置资源 owner 标识。
func (g *Group) SetOwnerID(ownerID string) { g.OwnerID = ownerID }

// IsRootGroup 检查是否为根组织
func (g *Group) IsRootGroup() bool {
	return g.ParentID == nil
}

// GetLevel 获取组织层级
func (g *Group) GetLevel() int {
	if g.Level <= 0 {
		return 1
	}
	return g.Level
}

// SetParent 设置父组织
func (g *Group) SetParent(parent *Group) {
	if parent == nil {
		g.Parent = nil
		g.ParentID = nil
		g.ParentKey = 0
		g.Level = 1
		if g.GetID() > 0 {
			g.Path = "/" + strconv.FormatInt(g.GetID(), 10)
		} else {
			g.Path = ""
		}
	} else {
		g.Parent = parent
		g.ParentID = &parent.ID
		g.ParentKey = parent.ID
		g.Level = parent.Level + 1
		if g.GetID() > 0 {
			g.Path = parent.Path + "/" + strconv.FormatInt(g.GetID(), 10)
		} else {
			g.Path = ""
		}
	}
	g.SetUpdatedAt(time.Now())
}

// UpdatePath 更新层级路径
func (g *Group) UpdatePath() {
	if g.ParentID == nil {
		g.Path = "/" + strconv.FormatInt(g.GetID(), 10)
		g.Level = 1
	} else if g.Parent != nil {
		g.Path = g.Parent.Path + "/" + strconv.FormatInt(g.GetID(), 10)
		g.Level = g.Parent.Level + 1
	}
}

// GetPathIDs 获取路径中的所有ID
func (g *Group) GetPathIDs() []int64 {
	if g.Path == "" {
		return []int64{}
	}

	parts := strings.Split(strings.Trim(g.Path, "/"), "/")
	ids := make([]int64, 0, len(parts))

	for _, part := range parts {
		if part != "" {
			if id, err := strconv.ParseInt(part, 10, 64); err == nil {
				ids = append(ids, id)
			}
		}
	}

	return ids
}

// IsAncestorOf 检查是否为指定组织的祖先
func (g *Group) IsAncestorOf(other *Group) bool {
	if other == nil || other.Path == "" {
		return false
	}

	myPath := g.Path + "/"
	return strings.HasPrefix(other.Path, myPath)
}

// IsDescendantOf 检查是否为指定组织的后代
func (g *Group) IsDescendantOf(other *Group) bool {
	if other == nil {
		return false
	}
	return other.IsAncestorOf(g)
}

// AddUser 添加用户到组织
func (g *Group) AddUser(user *User) {
	// 检查用户是否已存在
	for _, existingUser := range g.Users {
		if existingUser.GetID() == user.GetID() {
			return // 用户已存在，不重复添加
		}
	}
	g.Users = append(g.Users, user)
	g.SetUpdatedAt(time.Now())
}

// RemoveUser 从组织中移除用户
func (g *Group) RemoveUser(userID int64) {
	for i, user := range g.Users {
		if user.GetID() == userID {
			g.Users = append(g.Users[:i], g.Users[i+1:]...)
			g.SetUpdatedAt(time.Now())
			break
		}
	}
}

// HasUser 检查组织是否包含指定用户
func (g *Group) HasUser(userID int64) bool {
	for _, user := range g.Users {
		if user.GetID() == userID {
			return true
		}
	}
	return false
}

// AddDefaultRole 添加默认角色
func (g *Group) AddDefaultRole(role *Role) {
	// 检查角色是否已存在
	for _, existingRole := range g.DefaultRoles {
		if existingRole.GetID() == role.GetID() {
			return // 角色已存在，不重复添加
		}
	}
	g.DefaultRoles = append(g.DefaultRoles, role)
	g.SetUpdatedAt(time.Now())
}

// RemoveDefaultRole 移除默认角色
func (g *Group) RemoveDefaultRole(roleID int64) {
	for i, role := range g.DefaultRoles {
		if role.GetID() == roleID {
			g.DefaultRoles = append(g.DefaultRoles[:i], g.DefaultRoles[i+1:]...)
			g.SetUpdatedAt(time.Now())
			break
		}
	}
}

// UserCount 获取用户数量
func (g *Group) UserCount() int {
	return len(g.Users)
}

// FullName 获取完整名称（包含层级）
func (g *Group) FullName() string {
	if g.Parent == nil {
		return g.Name
	}
	return g.Parent.FullName() + " / " + g.Name
}

// String 返回字符串表示。
func (g *Group) String() string {
	return fmt.Sprintf("Group{ID: %d, Name: %s, Level: %d, Path: %s}",
		g.GetID(), g.Name, g.Level, g.Path)
}
