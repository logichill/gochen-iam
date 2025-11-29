package role

import (
	"context"
	ers "errors"

	iamentity "gochen-iam/entity"
	"gochen/data/orm"
	db "gochen/data/orm/repo"
	"gochen/domain/entity"
	"gochen/errors"
)

// RoleRepo 角色数据访问层
type RoleRepo struct{ *db.Repo[*iamentity.Role] }

// NewRoleRepository 创建角色Repository
func NewRoleRepository(o orm.IOrm) *RoleRepo {
	return &RoleRepo{Repo: db.NewRepo[*iamentity.Role](o, "roles")}
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// FindByName 根据角色名查找角色
func (r *RoleRepo) FindByName(ctx context.Context, name string) (*iamentity.Role, error) {
	var role iamentity.Role
	err := r.Model().First(ctx, &role,
		orm.WithWhere("name = ? AND deleted_at IS NULL", name),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		if ers.Is(err, orm.ErrNotFound) {
			return nil, errors.NewError(errors.ErrCodeNotFound, "角色不存在")
		}
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询角色失败")
	}

	return &role, nil
}

// FindByNames 根据角色名列表查找角色
func (r *RoleRepo) FindByNames(ctx context.Context, names []string) ([]*iamentity.Role, error) {
	if len(names) == 0 {
		return []*iamentity.Role{}, nil
	}

	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithWhere("name IN ? AND deleted_at IS NULL", names),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询角色失败")
	}

	return roles, nil
}

// FindByStatus 根据状态查找角色
func (r *RoleRepo) FindByStatus(ctx context.Context, status string) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithWhere("status = ? AND deleted_at IS NULL", status),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询角色失败")
	}

	return roles, nil
}

// FindSystemRoles 查找系统角色
func (r *RoleRepo) FindSystemRoles(ctx context.Context) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithWhere("is_system = ? AND deleted_at IS NULL", true),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询系统角色失败")
	}

	return roles, nil
}

// FindUserRoles 查找非系统角色（用户自定义角色）
func (r *RoleRepo) FindUserRoles(ctx context.Context) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithWhere("is_system = ? AND deleted_at IS NULL", false),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询用户角色失败")
	}

	return roles, nil
}

// FindByPermission 根据权限查找角色
func (r *RoleRepo) FindByPermission(ctx context.Context, permission string) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithWhere("JSON_CONTAINS(permissions, ?) AND deleted_at IS NULL", `"`+permission+`"`),
		orm.WithPreload("Users"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询角色失败")
	}

	return roles, nil
}

// FindByUserID 根据用户ID查找角色
func (r *RoleRepo) FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithJoin("JOIN user_roles ON roles.id = user_roles.role_id"),
		orm.WithWhere("user_roles.user_id = ? AND roles.deleted_at IS NULL", userID),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询用户角色失败")
	}

	return roles, nil
}

// FindByGroupID 根据组织ID查找默认角色
func (r *RoleRepo) FindByGroupID(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	err := r.Model().Find(ctx, &roles,
		orm.WithJoin("JOIN group_roles ON roles.id = group_roles.role_id"),
		orm.WithWhere("group_roles.group_id = ? AND roles.deleted_at IS NULL", groupID),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询组织角色失败")
	}

	return roles, nil
}

// AssignToUser 将角色分配给用户
func (r *RoleRepo) AssignToUser(ctx context.Context, roleID, userID int64) error {
	// 检查角色是否存在
	role, err := r.Repo.Get(ctx, roleID)
	if err != nil {
		return err
	}

	err = r.Association(role, "Users").
		Append(ctx, &iamentity.User{EntityFields: entity.EntityFields{ID: userID}})

	if err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "分配角色给用户失败")
	}

	return nil
}

// RemoveFromUser 从用户移除角色
func (r *RoleRepo) RemoveFromUser(ctx context.Context, roleID, userID int64) error {
	// 检查角色是否存在
	role, err := r.Repo.Get(ctx, roleID)
	if err != nil {
		return err
	}

	err = r.Association(role, "Users").
		Delete(ctx, &iamentity.User{EntityFields: entity.EntityFields{ID: userID}})

	if err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "从用户移除角色失败")
	}

	return nil
}

// AssignToGroup 将角色分配给组织作为默认角色
func (r *RoleRepo) AssignToGroup(ctx context.Context, roleID, groupID int64) error {
	// 检查角色是否存在
	role, err := r.Repo.Get(ctx, roleID)
	if err != nil {
		return err
	}

	err = r.Association(role, "Groups").
		Append(ctx, &iamentity.Group{EntityFields: entity.EntityFields{ID: groupID}})

	if err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "分配角色给组织失败")
	}

	return nil
}

// RemoveFromGroup 从组织移除默认角色
func (r *RoleRepo) RemoveFromGroup(ctx context.Context, roleID, groupID int64) error {
	// 检查角色是否存在
	role, err := r.Repo.Get(ctx, roleID)
	if err != nil {
		return err
	}

	err = r.Association(role, "Groups").
		Delete(ctx, &iamentity.Group{EntityFields: entity.EntityFields{ID: groupID}})

	if err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "从组织移除角色失败")
	}

	return nil
}

// CountByStatus 统计各状态角色数量
func (r *RoleRepo) CountByStatus(ctx context.Context) (map[string]int64, error) {
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	var results []StatusCount
	err := r.Model().Find(ctx, &results,
		orm.WithSelect("status", "COUNT(*) as count"),
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithGroupBy("status"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "统计角色状态失败")
	}

	statusMap := make(map[string]int64)
	for _, result := range results {
		statusMap[result.Status] = result.Count
	}

	return statusMap, nil
}

// GetRoleUsageStats 获取角色使用统计
func (r *RoleRepo) GetRoleUsageStats(ctx context.Context) ([]map[string]interface{}, error) {
	type RoleStats struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		UserCount  int64  `json:"user_count"`
		GroupCount int64  `json:"group_count"`
		IsSystem   bool   `json:"is_system"`
		Status     string `json:"status"`
	}

	var results []RoleStats
	err := r.Model().Find(ctx, &results,
		orm.WithSelect(`
			roles.id,
			roles.name,
			roles.is_system,
			roles.status,
			COALESCE(user_counts.user_count, 0) as user_count,
			COALESCE(group_counts.group_count, 0) as group_count
		`),
		orm.WithJoin(`
			LEFT JOIN (
				SELECT role_id, COUNT(*) as user_count 
				FROM user_roles 
				GROUP BY role_id
			) user_counts ON roles.id = user_counts.role_id
		`),
		orm.WithJoin(`
			LEFT JOIN (
				SELECT role_id, COUNT(*) as group_count 
				FROM group_roles 
				GROUP BY role_id
			) group_counts ON roles.id = group_counts.role_id
		`),
		orm.WithWhere("roles.deleted_at IS NULL"),
	)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "获取角色使用统计失败")
	}

	// 转换为通用格式
	stats := make([]map[string]interface{}, len(results))
	for i, result := range results {
		stats[i] = map[string]interface{}{
			"id":          result.ID,
			"name":        result.Name,
			"user_count":  result.UserCount,
			"group_count": result.GroupCount,
			"is_system":   result.IsSystem,
			"status":      result.Status,
		}
	}

	return stats, nil
}

// SearchRoles 搜索角色（支持名称、描述模糊搜索）
func (r *RoleRepo) SearchRoles(ctx context.Context, keyword string, limit int) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	opts := []orm.QueryOption{
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	}

	if keyword != "" {
		opts = append(opts, orm.WithWhere("name LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%"))
	}

	if limit > 0 {
		opts = append(opts, orm.WithLimit(limit))
	}

	err := r.Model().Find(ctx, &roles, opts...)

	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "搜索角色失败")
	}

	return roles, nil
}

// InitializeSystemRoles 初始化系统角色
func (r *RoleRepo) InitializeSystemRoles(ctx context.Context) error {
	systemRoles := []*iamentity.Role{
		iamentity.SystemAdminRole,
		iamentity.UserRole,
	}

	for _, role := range systemRoles {
		// 检查角色是否已存在
		existing, err := r.FindByName(ctx, role.Name)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		if existing == nil {
			// 角色不存在，创建它
			if err := r.Repo.Add(ctx, role); err != nil {
				return errors.WrapError(err, errors.ErrCodeDatabase, "初始化系统角色失败: "+role.Name)
			}
		}
	}

	return nil
}
