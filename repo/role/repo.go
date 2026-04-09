package role

import (
	"context"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	dataquery "gochen/db/query"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/ident"
)

// RoleRepo 角色数据访问层
type RoleRepo struct {
	*db.Repo[*iamentity.Role, int64]
}

// NewRoleRepository 创建角色仓储。
func NewRoleRepository(o orm.IOrm) (*RoleRepo, error) {
	base, err := db.NewRepo[*iamentity.Role, int64](
		o,
		"roles",
		db.WithIDGenerator[*iamentity.Role, int64](ident.DefaultInt64Generator()),
	)
	if err != nil {
		return nil, err
	}
	return &RoleRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Query 覆盖通用查询，补齐 namespace scope 关系。
func (r *RoleRepo) Query(ctx context.Context, opts dataquery.QueryOptions) ([]*iamentity.Role, error) {
	roles, err := r.Repo.Query(ctx, opts)
	if err != nil {
		return nil, err
	}
	return r.hydrateRoleScopes(ctx, roles)
}

// Get 根据ID获取角色（过滤软删记录）
func (r *RoleRepo) Get(ctx context.Context, id int64) (*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var role iamentity.Role
	err = model.First(ctx, &role, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "角色不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询角色失败")
	}
	roles, err := r.hydrateRoleScopes(ctx, []*iamentity.Role{&role})
	if err != nil {
		return nil, err
	}
	return roles[0], nil
}

// FindByName 根据角色名查找角色（租户内唯一）
func (r *RoleRepo) FindByName(ctx context.Context, tenantID, name string) (*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var role iamentity.Role
	err = model.First(ctx, &role,
		orm.WithWhere("tenant_id = ? AND name = ? AND deleted_at IS NULL", tenantID, name),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "角色不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询角色失败")
	}

	roles, err := r.hydrateRoleScopes(ctx, []*iamentity.Role{&role})
	if err != nil {
		return nil, err
	}
	return roles[0], nil
}

// FindByNames 根据角色名列表查找角色（租户隔离）
func (r *RoleRepo) FindByNames(ctx context.Context, tenantID string, names []string) ([]*iamentity.Role, error) {
	if len(names) == 0 {
		return []*iamentity.Role{}, nil
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithWhere("tenant_id = ? AND name IN ? AND deleted_at IS NULL", tenantID, names),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByStatus 根据状态查找角色（租户隔离）
func (r *RoleRepo) FindByStatus(ctx context.Context, tenantID, status string) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithWhere("tenant_id = ? AND status = ? AND deleted_at IS NULL", tenantID, status),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindSystemRoles 查找系统角色（租户隔离）
func (r *RoleRepo) FindSystemRoles(ctx context.Context, tenantID string) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithWhere("tenant_id = ? AND is_system = ? AND deleted_at IS NULL", tenantID, true),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询系统角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindUserRoles 查找非系统角色（用户自定义角色，租户隔离）
func (r *RoleRepo) FindUserRoles(ctx context.Context, tenantID string) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithWhere("tenant_id = ? AND is_system = ? AND deleted_at IS NULL", tenantID, false),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询用户角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByPermission 根据权限查找角色（租户隔离）
func (r *RoleRepo) FindByPermission(ctx context.Context, tenantID, permission string) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", tenantID),
		orm.WithPreload("Users"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询角色失败")
	}

	if permission == "" {
		return r.hydrateRoleScopes(ctx, roles)
	}

	filtered := make([]*iamentity.Role, 0, len(roles))
	for _, role := range roles {
		if role == nil {
			continue
		}
		for _, granted := range role.Permissions {
			if iammw.PermissionPatternMatches(granted, permission) {
				filtered = append(filtered, role)
				break
			}
		}
	}

	return r.hydrateRoleScopes(ctx, filtered)
}

// FindByUserID 根据用户ID查找角色（租户隔离）
func (r *RoleRepo) FindByUserID(ctx context.Context, tenantID string, userID int64) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithJoin(orm.InnerJoin("user_roles", "", orm.On("roles.id", "user_roles.role_id"))),
		orm.WithWhere("user_roles.user_id = ? AND roles.tenant_id = ? AND roles.deleted_at IS NULL", userID, tenantID),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询用户角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByGroupID 根据组织ID查找默认角色（租户隔离）
func (r *RoleRepo) FindByGroupID(ctx context.Context, tenantID string, groupID int64) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = model.Find(ctx, &roles,
		orm.WithJoin(orm.InnerJoin("group_roles", "", orm.On("roles.id", "group_roles.role_id"))),
		orm.WithWhere("group_roles.group_id = ? AND roles.tenant_id = ? AND roles.deleted_at IS NULL", groupID, tenantID),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询组织角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// AssignToUser 将角色分配给用户
func (r *RoleRepo) AssignToUser(ctx context.Context, roleID, userID int64) error {
	// 检查角色是否存在
	role, err := r.Repo.Get(ctx, roleID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Users").
		Append(ctx, &iamentity.User{Entity: crud.Entity[int64]{ID: userID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "分配角色给用户失败")
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

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Users").
		Delete(ctx, &iamentity.User{Entity: crud.Entity[int64]{ID: userID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "从用户移除角色失败")
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

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Groups").
		Append(ctx, &iamentity.Group{Entity: crud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "分配角色给组织失败")
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

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Groups").
		Delete(ctx, &iamentity.Group{Entity: crud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "从组织移除角色失败")
	}

	return nil
}

// CountByStatus 统计各状态角色数量（租户隔离）
func (r *RoleRepo) CountByStatus(ctx context.Context, tenantID string) (map[string]int64, error) {
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	var results []StatusCount
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	err = model.Find(ctx, &results,
		orm.WithSelect("status", "COUNT(*) as count"),
		orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", tenantID),
		orm.WithGroupBy("status"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "统计角色状态失败")
	}

	statusMap := make(map[string]int64)
	for _, result := range results {
		statusMap[result.Status] = result.Count
	}

	return statusMap, nil
}

// GetRoleUsageStats 获取角色使用统计
func (r *RoleRepo) GetRoleUsageStats(ctx context.Context) ([]map[string]interface{}, error) {
	type roleBase struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		IsSystem bool   `json:"is_system"`
		Status   string `json:"status"`
	}

	var roles []roleBase
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	if err := model.Find(ctx, &roles,
		orm.WithSelect("id", "name", "is_system", "status"),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "获取角色列表失败")
	}

	ids := make([]int64, 0, len(roles))
	for i := range roles {
		ids = append(ids, roles[i].ID)
	}

	type roleCount struct {
		RoleID int64 `json:"role_id"`
		Count  int64 `json:"count"`
	}

	userCounts := make(map[int64]int64, len(ids))
	groupCounts := make(map[int64]int64, len(ids))

	if len(ids) > 0 {
		engine := r.Orm()
		if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
			engine = session
		}

		userRoleModel, err := engine.Model(&orm.ModelMeta{
			ModelFactory: orm.NewModelFactory[struct {
				RoleID int64
				UserID int64
			}](),
			Table: "user_roles",
		})
		if err != nil {
			return nil, errorx.Wrap(err, errorx.Database, "初始化 user_roles 模型失败")
		}

		var rows []roleCount
		if err := userRoleModel.Find(ctx, &rows,
			orm.WithSelect("role_id", "COUNT(*) as count"),
			orm.WithWhere("role_id IN ?", ids),
			orm.WithGroupBy("role_id"),
		); err != nil {
			return nil, errorx.Wrap(err, errorx.Database, "统计角色用户数量失败")
		}
		for i := range rows {
			userCounts[rows[i].RoleID] = rows[i].Count
		}

		groupRoleModel, err := engine.Model(&orm.ModelMeta{
			ModelFactory: orm.NewModelFactory[struct {
				RoleID  int64
				GroupID int64
			}](),
			Table: "group_roles",
		})
		if err != nil {
			return nil, errorx.Wrap(err, errorx.Database, "初始化 group_roles 模型失败")
		}
		rows = nil
		if err := groupRoleModel.Find(ctx, &rows,
			orm.WithSelect("role_id", "COUNT(*) as count"),
			orm.WithWhere("role_id IN ?", ids),
			orm.WithGroupBy("role_id"),
		); err != nil {
			return nil, errorx.Wrap(err, errorx.Database, "统计角色组织数量失败")
		}
		for i := range rows {
			groupCounts[rows[i].RoleID] = rows[i].Count
		}
	}

	// 转换为通用格式
	stats := make([]map[string]interface{}, len(roles))
	for i := range roles {
		roleID := roles[i].ID
		stats[i] = map[string]interface{}{
			"id":          roleID,
			"name":        roles[i].Name,
			"user_count":  userCounts[roleID],
			"group_count": groupCounts[roleID],
			"is_system":   roles[i].IsSystem,
			"status":      roles[i].Status,
		}
	}

	return stats, nil
}

// SearchRoles 搜索角色（支持名称、描述模糊搜索，租户隔离）
func (r *RoleRepo) SearchRoles(ctx context.Context, tenantID, keyword string, limit int) ([]*iamentity.Role, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	opts := []orm.QueryOption{
		orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", tenantID),
		orm.WithPreload("Users"),
		orm.WithPreload("Groups"),
	}

	if keyword != "" {
		opts = append(opts, orm.WithWhere("name LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%"))
	}

	if limit > 0 {
		opts = append(opts, orm.WithLimit(limit))
	}

	err = model.Find(ctx, &roles, opts...)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "搜索角色失败")
	}

	return roles, nil
}

// CountGroupsByRoleID 统计使用指定角色作为默认角色的组织数量（不依赖 preload）
func (r *RoleRepo) CountGroupsByRoleID(ctx context.Context, roleID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	groupRoleModel, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[struct {
			RoleID  int64
			GroupID int64
		}](),
		Table: "group_roles",
	})
	if err != nil {
		return 0, errorx.Wrap(err, errorx.Database, "初始化 group_roles 模型失败")
	}
	count, err := groupRoleModel.Count(ctx, orm.WithWhere("role_id = ?", roleID))
	if err != nil {
		return 0, errorx.Wrap(err, errorx.Database, "统计角色组织数量失败")
	}
	return count, nil
}

// InitializeSystemRoles 初始化系统角色（租户维度）
func (r *RoleRepo) InitializeSystemRoles(ctx context.Context, tenantID string) error {
	systemRoles := []*iamentity.Role{
		iamentity.SystemAdminRole,
		iamentity.UserRole,
	}

	for _, role := range systemRoles {
		// 检查角色是否已存在
		existing, err := r.FindByName(ctx, tenantID, role.Name)
		if err != nil && !errorx.Is(err, errorx.NotFound) {
			return err
		}

		if existing == nil {
			// 角色不存在，创建它
			clone := *role
			clone.TenantID = tenantID
			if err := r.Repo.Create(ctx, &clone); err != nil {
				return errorx.Wrap(err, errorx.Database, "初始化系统角色失败: "+role.Name)
			}
		}
	}

	return nil
}

func (r *RoleRepo) hydrateRoleScopes(ctx context.Context, roles []*iamentity.Role) ([]*iamentity.Role, error) {
	if len(roles) == 0 {
		return roles, nil
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	scopeModel, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Scope](),
		Table:        "scopes",
	})
	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "初始化 scopes 模型失败")
	}

	for _, role := range roles {
		if role == nil || role.NamespaceScopeID <= 0 {
			continue
		}
		var scope iamentity.Scope
		if err := scopeModel.First(ctx, &scope, orm.WithWhere("id = ? AND deleted_at IS NULL", role.NamespaceScopeID)); err != nil {
			if errorx.Is(err, errorx.NotFound) {
				continue
			}
			return nil, errorx.Wrap(err, errorx.Database, "查询 namespace scope 失败")
		}
		role.NamespaceScope = &scope
	}
	return roles, nil
}
