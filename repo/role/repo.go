package role

import (
	"context"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	appcrud "gochen/app/crud"
	"gochen/auth/access"
	auth "gochen/auth/core"
	"gochen/db/orm"
	"gochen/db/orm/repo"
	"gochen/db/query"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
	"gochen/ident"
)

// RoleRepo 角色数据访问层
type RoleRepo struct {
	*repo.Repo[*iamentity.Role, int64]
}

const (
	roleResourceKind  = "iam.role"
	userResourceKind  = "iam.user"
	groupResourceKind = "iam.group"
)

func (r *RoleRepo) tenantScopedQuery(ctx context.Context) (*repo.ScopedQuery, error) {
	query, err := r.Repo.ScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	return query.Where("tenant_id = ?", tenantID), nil
}

func (r *RoleRepo) findOne(ctx context.Context, configure func(*repo.ScopedQuery)) (*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	if configure != nil {
		configure(query)
	}
	var role *iamentity.Role
	if err := query.First(&role); err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepo) getByID(ctx context.Context, id int64) (*iamentity.Role, error) {
	return r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("id = ?", id)
	})
}

// NewRoleRepository 创建角色仓储。
func NewRoleRepository(o orm.IOrm) (*RoleRepo, error) {
	base, err := repo.NewRepo[*iamentity.Role, int64](
		o,
		"roles",
		repo.WithIDGenerator[*iamentity.Role, int64](ident.DefaultInt64Generator()),
		repo.WithResourceKind[*iamentity.Role, int64]("iam.role"),
		repo.WithSoftDeleteColumns[*iamentity.Role, int64]("deleted_at", ""),
		repo.WithAccessColumns[*iamentity.Role, int64]("namespace_scope_id", "owner_id", "version"),
	)
	if err != nil {
		return nil, err
	}
	return &RoleRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

func (r *RoleRepo) Create(ctx context.Context, role *iamentity.Role) error {
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err == nil {
		if role.TenantID == "" {
			role.TenantID = tenantID
		} else if role.TenantID != tenantID {
			return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
		}
	} else if !errors.Is(err, errors.InvalidInput) {
		return err
	}
	if role.OwnerID == "" {
		role.OwnerID = tenantOwnerID(role.TenantID)
	}
	if role.NamespaceScopeID == 0 {
		role.NamespaceScopeID = managedScopeFromContext(ctx)
	}
	return r.Repo.Create(ctx, role)
}

func (r *RoleRepo) Update(ctx context.Context, role *iamentity.Role) error {
	tenantID, err := appcrud.ResolveTenantID(ctx)
	if err != nil {
		return err
	}
	if role.TenantID == "" {
		role.TenantID = tenantID
	} else if role.TenantID != tenantID {
		return errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
	}
	if role.OwnerID == "" {
		role.OwnerID = tenantOwnerID(role.TenantID)
	}
	if role.NamespaceScopeID == 0 {
		role.NamespaceScopeID = managedScopeFromContext(ctx)
	}
	return r.Repo.Update(ctx, roleWithoutAssociations(role))
}

func roleWithoutAssociations(role *iamentity.Role) *iamentity.Role {
	if role == nil {
		return nil
	}
	clone := *role
	clone.NamespaceScope = nil
	clone.Users = nil
	clone.Groups = nil
	return &clone
}

func (r *RoleRepo) CreateWithConstraint(ctx context.Context, role *iamentity.Role, guard iamaccess.WriteConstraint) error {
	return r.Repo.CreateWithConstraint(assocguard.BindContext(ctx, guard), role, guard.Unwrap())
}

func (r *RoleRepo) UpdateWithConstraint(ctx context.Context, role *iamentity.Role, guard iamaccess.WriteConstraint) error {
	return r.Repo.UpdateWithConstraint(assocguard.BindContext(ctx, guard), role, guard.Unwrap())
}

func (r *RoleRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
}

// Query 覆盖通用查询，补齐 namespace scope 关系。
func (r *RoleRepo) Query(ctx context.Context, opts query.QueryOptions) ([]*iamentity.Role, error) {
	roles, err := r.Repo.Query(ctx, opts)
	if err != nil {
		return nil, err
	}
	return r.hydrateRoleScopes(ctx, roles)
}

// Get 根据ID获取角色。
func (r *RoleRepo) Get(ctx context.Context, id int64) (*iamentity.Role, error) {
	role, err := r.getByID(ctx, id)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}
	roles, err := r.hydrateRoleScopes(ctx, []*iamentity.Role{role})
	if err != nil {
		return nil, err
	}
	return roles[0], nil
}

// FindByName 根据角色名查找角色（租户内唯一）。
func (r *RoleRepo) FindByName(ctx context.Context, name string) (*iamentity.Role, error) {
	role, err := r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("name = ?", name).Preload("Users", "Groups")
	})
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}

	roles, err := r.hydrateRoleScopes(ctx, []*iamentity.Role{role})
	if err != nil {
		return nil, err
	}
	return roles[0], nil
}

// FindByNames 根据角色名列表查找角色。
func (r *RoleRepo) FindByNames(ctx context.Context, names []string) ([]*iamentity.Role, error) {
	if len(names) == 0 {
		return []*iamentity.Role{}, nil
	}

	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Where("name IN ?", names).
		Preload("Users", "Groups").
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByStatus 根据状态查找角色。
func (r *RoleRepo) FindByStatus(ctx context.Context, status string) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Where("status = ?", status).
		Preload("Users", "Groups").
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindSystemRoles 查找系统角色。
func (r *RoleRepo) FindSystemRoles(ctx context.Context) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.Where("is_system = ?", true).Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询系统角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

func (r *RoleRepo) CountByNamespaceScopeID(ctx context.Context, scopeID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Role](),
		Table:        "roles",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 roles 模型失败")
	}
	count, err := model.Count(ctx,
		orm.WithWhere("namespace_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计角色 namespace scope 引用失败")
	}
	return count, nil
}

// FindUserRoles 查找非系统角色（用户自定义角色）。
func (r *RoleRepo) FindUserRoles(ctx context.Context) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Where("is_system = ?", false).
		Preload("Users", "Groups").
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询用户角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByPermission 根据权限查找角色。
func (r *RoleRepo) FindByPermission(ctx context.Context, permission string) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.Preload("Users").Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}

	if permission == "" {
		return r.hydrateRoleScopes(ctx, roles)
	}

	filtered := make([]*iamentity.Role, 0, len(roles))
	for _, role := range roles {
		if role == nil {
			continue
		}
		if (auth.Principal{Permissions: role.Permissions}).AllowsPermission(permission) {
			filtered = append(filtered, role)
		}
	}

	return r.hydrateRoleScopes(ctx, filtered)
}

// FindByUserID 根据用户ID查找角色。
func (r *RoleRepo) FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Join(orm.InnerJoin("user_role_bindings", "", orm.On("roles.id", "user_role_bindings.role_id"))).
		Where("user_role_bindings.user_id = ?", userID).
		Where("user_role_bindings.status = ?", "active").
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询用户角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// FindByGroupID 根据组织ID查找默认角色。
func (r *RoleRepo) FindByGroupID(ctx context.Context, groupID int64) ([]*iamentity.Role, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Join(orm.InnerJoin("group_roles", "", orm.On("roles.id", "group_roles.role_id"))).
		Where("group_roles.group_id = ?", groupID).
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询组织角色失败")
	}

	return r.hydrateRoleScopes(ctx, roles)
}

// AssignToUser 将角色分配给用户
func (r *RoleRepo) AssignToUser(ctx context.Context, roleID, userID int64) error {
	// 检查角色是否存在
	role, err := r.getByID(ctx, roleID)
	if err != nil {
		return err
	}

	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	grantScopeID := role.NamespaceScopeID
	if override := managedScopeFromContext(ctx); override > 0 {
		grantScopeID = override
	}
	if err := model.Create(ctx, &iamentity.UserRoleBinding{
		UserID:       userID,
		RoleID:       roleID,
		GrantScopeID: grantScopeID,
		Status:       "active",
	}); err != nil {
		return errors.Wrap(err, errors.Database, "分配角色给用户失败")
	}

	return nil
}

// AssignToUserWithConstraint 在显式多资源写边界下给用户分配角色。
func (r *RoleRepo) AssignToUserWithConstraint(ctx context.Context, roleID, userID int64, guard iamaccess.WriteConstraint) error {
	if _, _, err := assocguard.RequirePair(guard, roleResourceKind, roleID, userResourceKind, userID); err != nil {
		return err
	}
	return r.AssignToUser(assocguard.BindContext(ctx, guard), roleID, userID)
}

// RemoveFromUser 从用户移除角色
func (r *RoleRepo) RemoveFromUser(ctx context.Context, roleID, userID int64) error {
	// 检查角色是否存在
	if _, err := r.getByID(ctx, roleID); err != nil {
		return err
	}

	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	if err := model.Delete(ctx,
		orm.WithWhere("role_id = ?", roleID),
		orm.WithWhere("user_id = ?", userID),
	); err != nil {
		return errors.Wrap(err, errors.Database, "从用户移除角色失败")
	}

	return nil
}

// RemoveFromUserWithConstraint 在显式多资源写边界下移除用户角色。
func (r *RoleRepo) RemoveFromUserWithConstraint(ctx context.Context, roleID, userID int64, guard iamaccess.WriteConstraint) error {
	if _, _, err := assocguard.RequirePair(guard, roleResourceKind, roleID, userResourceKind, userID); err != nil {
		return err
	}
	return r.RemoveFromUser(assocguard.BindContext(ctx, guard), roleID, userID)
}

// AssignToGroup 将角色分配给组织作为默认角色
func (r *RoleRepo) AssignToGroup(ctx context.Context, roleID, groupID int64) error {
	// 检查角色是否存在
	role, err := r.getByID(ctx, roleID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Groups").
		Append(ctx, &iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "分配角色给组织失败")
	}

	return nil
}

// AssignToGroupWithConstraint 在显式多资源写边界下给组织分配默认角色。
func (r *RoleRepo) AssignToGroupWithConstraint(ctx context.Context, roleID, groupID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateRoleAssociationWithConstraint(
		ctx,
		roleID,
		"Groups",
		groupResourceKind,
		groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}},
		false,
		"分配角色给组织失败",
		guard,
	)
}

// RemoveFromGroup 从组织移除默认角色
func (r *RoleRepo) RemoveFromGroup(ctx context.Context, roleID, groupID int64) error {
	// 检查角色是否存在
	role, err := r.getByID(ctx, roleID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(role, "Groups").
		Delete(ctx, &iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "从组织移除角色失败")
	}

	return nil
}

// RemoveFromGroupWithConstraint 在显式多资源写边界下移除组织默认角色。
func (r *RoleRepo) RemoveFromGroupWithConstraint(ctx context.Context, roleID, groupID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateRoleAssociationWithConstraint(
		ctx,
		roleID,
		"Groups",
		groupResourceKind,
		groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}},
		true,
		"从组织移除角色失败",
		guard,
	)
}

func (r *RoleRepo) mutateRoleAssociationWithConstraint(
	ctx context.Context,
	roleID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	guard iamaccess.WriteConstraint,
) error {
	if _, _, err := assocguard.RequirePair(guard, roleResourceKind, roleID, relatedKind, relatedID); err != nil {
		return err
	}

	role, err := r.getByID(ctx, roleID)
	if err != nil {
		return err
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}

	associationRef := model.Association(role, association)
	if remove {
		err = associationRef.Delete(ctx, related)
	} else {
		err = associationRef.Append(ctx, related)
	}
	if err != nil {
		return errors.Wrap(err, errors.Database, message)
	}
	return nil
}

// CountByStatus 统计各状态角色数量。
func (r *RoleRepo) CountByStatus(ctx context.Context) (map[string]int64, error) {
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	var results []StatusCount
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Select("status", "COUNT(*) as count").
		GroupBy("status").
		Find(&results)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "统计角色状态失败")
	}

	statusMap := make(map[string]int64)
	for _, result := range results {
		statusMap[result.Status] = result.Count
	}

	return statusMap, nil
}

// RoleUsageStats 获取角色使用统计
func (r *RoleRepo) RoleUsageStats(ctx context.Context) ([]map[string]interface{}, error) {
	type roleBase struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		IsSystem bool   `json:"is_system"`
		Status   string `json:"status"`
	}

	var roles []roleBase
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	if err := query.Select("id", "name", "is_system", "status").Find(&roles); err != nil {
		return nil, errors.Wrap(err, errors.Database, "获取角色列表失败")
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
			Table: "user_role_bindings",
		})
		if err != nil {
			return nil, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
		}

		var rows []roleCount
		if err := userRoleModel.Find(ctx, &rows,
			orm.WithSelect("role_id", "COUNT(*) as count"),
			orm.WithWhere("role_id IN ?", ids),
			orm.WithWhere("status = ?", "active"),
			orm.WithGroupBy("role_id"),
		); err != nil {
			return nil, errors.Wrap(err, errors.Database, "统计角色用户数量失败")
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
			return nil, errors.Wrap(err, errors.Database, "初始化 group_roles 模型失败")
		}
		rows = nil
		if err := groupRoleModel.Find(ctx, &rows,
			orm.WithSelect("role_id", "COUNT(*) as count"),
			orm.WithWhere("role_id IN ?", ids),
			orm.WithGroupBy("role_id"),
		); err != nil {
			return nil, errors.Wrap(err, errors.Database, "统计角色组织数量失败")
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

// SearchRoles 搜索角色（支持名称、描述模糊搜索）。
func (r *RoleRepo) SearchRoles(ctx context.Context, keyword string, limit int) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	query.Preload("Users", "Groups")
	if keyword != "" {
		query.Where("name LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if limit > 0 {
		query.Limit(limit)
	}
	err = query.Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "搜索角色失败")
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
		return 0, errors.Wrap(err, errors.Database, "初始化 group_roles 模型失败")
	}
	count, err := groupRoleModel.Count(ctx, orm.WithWhere("role_id = ?", roleID))
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计角色组织数量失败")
	}
	return count, nil
}

// InitializeSystemRoles 初始化系统角色。
func (r *RoleRepo) InitializeSystemRoles(ctx context.Context) error {
	systemRoles := []*iamentity.Role{
		iamentity.SystemAdminRole,
		iamentity.UserRole,
	}

	for _, role := range systemRoles {
		// 检查角色是否已存在
		existing, err := r.FindByName(ctx, role.Name)
		if err != nil && !errors.Is(err, errors.NotFound) {
			return err
		}

		if existing == nil {
			// 角色不存在，创建它
			clone := *role
			if err := r.Repo.Create(ctx, &clone); err != nil {
				return errors.Wrap(err, errors.Database, "初始化系统角色失败: "+role.Name)
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
		return nil, errors.Wrap(err, errors.Database, "初始化 scopes 模型失败")
	}

	for _, role := range roles {
		if role == nil || role.NamespaceScopeID <= 0 {
			continue
		}
		var scope iamentity.Scope
		if err := scopeModel.First(ctx, &scope, orm.WithWhere("id = ? AND deleted_at IS NULL", role.NamespaceScopeID)); err != nil {
			if errors.Is(err, errors.NotFound) {
				continue
			}
			return nil, errors.Wrap(err, errors.Database, "查询 namespace scope 失败")
		}
		role.NamespaceScope = &scope
	}
	return roles, nil
}

func managedScopeFromContext(ctx context.Context) int64 {
	if scopeID := iamauth.ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scopeID
	}
	if scope, ok := auth.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if scope, ok := access.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if principal, ok := auth.PrincipalFromContext(ctx); ok && principal.ActiveScopeID > 0 {
		return principal.ActiveScopeID
	}
	return 0
}

func tenantOwnerID(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return "tenant:" + tenantID
}
