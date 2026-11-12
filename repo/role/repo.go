package role

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen-iam/repo/internal/likesafe"
	scoperesolver "gochen-iam/repo/internal/scope"
	"gochen-iam/repo/relations"
	iamtenant "gochen-iam/tenant"
	"gochen-runtime/db/orm/repo"
	auth "gochen-runtime/host/authz"
	"gochen/app/query"
	"gochen/db/orm"
	domaincrud "gochen/domain/crud"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/gen"
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
	query, err := r.ScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
func NewRoleRepository(o orm.IOrm, idGenerator gen.IGenerator[int64]) (*RoleRepo, error) {
	base, err := repo.NewRepo[*iamentity.Role, int64](
		o,
		"roles",
		repo.WithIDGenerator[*iamentity.Role, int64](idGenerator),
		repo.WithResourceKind[*iamentity.Role, int64]("iam.role"),
		repo.WithSoftDeleteColumns[*iamentity.Role, int64]("deleted_at", ""),
		repo.WithIsolation[*iamentity.Role, int64](repo.IsolationCols{Column: "tenant_id"}),
	)
	if err != nil {
		return nil, err
	}
	return &RoleRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

func (r *RoleRepo) Create(ctx context.Context, role *iamentity.Role, s spec.Spec) error {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
		role.NamespaceScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	return r.Repo.Create(ctx, role, s)
}

func (r *RoleRepo) Update(ctx context.Context, role *iamentity.Role, s spec.Spec) error {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
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
		role.NamespaceScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	updated := roleWithoutAssociations(role)
	if err := r.Repo.Update(ctx, updated, s); err != nil {
		return err
	}
	role.Version = updated.Version
	role.Timestamps = updated.Timestamps
	return nil
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

// Delete 执行软删除并保留 IAM 既有语义；物理删除请使用 Purge。
func (r *RoleRepo) Delete(ctx context.Context, role *iamentity.Role, s spec.Spec) error {
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role cannot be nil")
	}
	if role.IsDeleted() {
		return errors.NewCode(errors.Conflict, "角色已删除").WithContext("id", role.GetID())
	}
	role.MarkAsDeleted()
	return r.Update(ctx, role, s)
}

// Query 覆盖通用查询，补齐 namespace scope 关系。
func (r *RoleRepo) Query(ctx context.Context, opts query.QueryOptions, s spec.Spec) ([]*iamentity.Role, error) {
	roles, err := r.Repo.Query(ctx, opts, s)
	if err != nil {
		return nil, err
	}
	return r.hydrateRoleScopes(ctx, roles)
}

// Get 根据ID获取角色。
func (r *RoleRepo) Get(ctx context.Context, id int64, s spec.Spec) (*iamentity.Role, error) {
	role, err := r.Repo.Get(ctx, id, s)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "角色不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询角色失败")
	}
	return role, nil
}

// FindByIDs 根据角色 ID 列表批量查找角色。
func (r *RoleRepo) FindByIDs(ctx context.Context, ids []int64) ([]*iamentity.Role, error) {
	if len(ids) == 0 {
		return []*iamentity.Role{}, nil
	}
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	if err := query.Where("id IN ?", ids).Find(&roles); err != nil {
		return nil, errors.Wrap(err, errors.Database, "批量查询角色失败")
	}
	return r.hydrateRoleScopes(ctx, roles)
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
	return r.FindByGroupIDs(ctx, []int64{groupID})
}

func (r *RoleRepo) RolesForGroups(ctx context.Context, groupIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
	return relations.Read(ctx, r.Repo, groupIDs, condition, orm.InnerJoin("group_roles", "", orm.On("roles.id", "group_roles.role_id")), "group_roles.group_id", "roles.id")
}

func (r *RoleRepo) RolesForUsers(ctx context.Context, userIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
	return relations.Read(ctx, r.Repo, userIDs, condition, orm.InnerJoin("user_role_bindings", "", orm.On("roles.id", "user_role_bindings.role_id")), "user_role_bindings.user_id", "roles.id")
}

// ActiveRolesForUser applies binding status before projecting role associations.
func (r *RoleRepo) ActiveRolesForUser(ctx context.Context, userID int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
	return relations.Read(ctx, r.Repo, []int64{userID}, condition,
		orm.InnerJoin("user_role_bindings", "", orm.On("roles.id", "user_role_bindings.role_id")),
		"user_role_bindings.user_id", "roles.id", orm.Condition{Expr: "user_role_bindings.status = ?", Args: []any{"active"}})
}

// FindByGroupIDs 根据组织 ID 列表批量查找默认角色。
func (r *RoleRepo) FindByGroupIDs(ctx context.Context, groupIDs []int64) ([]*iamentity.Role, error) {
	if len(groupIDs) == 0 {
		return []*iamentity.Role{}, nil
	}
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	var roles []*iamentity.Role
	err = query.
		Join(orm.InnerJoin("group_roles", "", orm.On("roles.id", "group_roles.role_id"))).
		Where("group_roles.group_id IN ?", groupIDs).
		Find(&roles)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询组织角色失败")
	}

	uniqueRoles := make([]*iamentity.Role, 0, len(roles))
	seen := make(map[int64]struct{}, len(roles))
	for _, role := range roles {
		if role == nil {
			continue
		}
		if _, ok := seen[role.GetID()]; ok {
			continue
		}
		seen[role.GetID()] = struct{}{}
		uniqueRoles = append(uniqueRoles, role)
	}
	return r.hydrateRoleScopes(ctx, uniqueRoles)
}

// AssignToUser 将角色分配给用户。
func (r *RoleRepo) AssignToUser(ctx context.Context, roleID, userID int64, s spec.Spec) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		role, err := r.Repo.Get(txCtx, roleID, s)
		if err != nil {
			return err
		}
		user, err := r.userByID(txCtx, userID)
		if err != nil {
			return err
		}
		if err := requireSpecMatch(s, user); err != nil {
			return err
		}
		grantScopeID := role.NamespaceScopeID
		if override := scoperesolver.ResolveManagedScopeID(txCtx); override > 0 {
			grantScopeID = override
		}
		engine := r.Orm()
		if session, ok := orm.SessionFromContext(txCtx); ok && session != nil {
			engine = session
		}
		bindingModel, err := engine.Model(&orm.ModelMeta{
			ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
			Table:        "user_role_bindings",
		})
		if err != nil {
			return errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
		}
		if err := bindingModel.Create(txCtx, &iamentity.UserRoleBinding{
			UserID:       userID,
			RoleID:       roleID,
			GrantScopeID: grantScopeID,
			Status:       "active",
		}); err != nil {
			return errors.Wrap(err, errors.Database, "分配角色给用户失败")
		}
		return nil
	})
}

// RemoveFromUser 从用户移除角色。
func (r *RoleRepo) RemoveFromUser(ctx context.Context, roleID, userID int64, s spec.Spec) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		if _, err := r.Repo.Get(txCtx, roleID, s); err != nil {
			return err
		}
		user, err := r.userByID(txCtx, userID)
		if err != nil {
			return err
		}
		if err := requireSpecMatch(s, user); err != nil {
			return err
		}
		model, err := r.userRoleBindingModel(txCtx)
		if err != nil {
			return err
		}
		if err := model.Delete(txCtx,
			orm.WithWhere("role_id = ?", roleID),
			orm.WithWhere("user_id = ?", userID),
		); err != nil {
			return errors.Wrap(err, errors.Database, "从用户移除角色失败")
		}
		return nil
	})
}

// AssignToGroup 将角色分配给组织作为默认角色。
func (r *RoleRepo) AssignToGroup(ctx context.Context, roleID, groupID int64, s spec.Spec) error {
	return r.mutateRoleAssociation(ctx, roleID, "Groups", groupResourceKind, groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}}, false, "分配角色给组织失败", s)
}

// RemoveFromGroup 从组织移除默认角色。
func (r *RoleRepo) RemoveFromGroup(ctx context.Context, roleID, groupID int64, s spec.Spec) error {
	return r.mutateRoleAssociation(ctx, roleID, "Groups", groupResourceKind, groupID,
		&iamentity.Group{Entity: domaincrud.Entity[int64]{ID: groupID}}, true, "从组织移除角色失败", s)
}

func (r *RoleRepo) mutateRoleAssociation(
	ctx context.Context,
	roleID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	s spec.Spec,
) error {
	if err := r.requireRelatedInSpec(ctx, relatedKind, relatedID, s); err != nil {
		return err
	}
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		role, err := r.Repo.Get(txCtx, roleID, s)
		if err != nil {
			return err
		}
		model, err := r.ModelFor(txCtx)
		if err != nil {
			return err
		}
		associationRef := model.Association(role, association)
		if remove {
			err = associationRef.Delete(txCtx, related)
		} else {
			err = associationRef.Append(txCtx, related)
		}
		if err != nil {
			return errors.Wrap(err, errors.Database, message)
		}
		return nil
	})
}

func (r *RoleRepo) requireRelatedInSpec(ctx context.Context, kind string, id int64, s spec.Spec) error {
	switch kind {
	case userResourceKind:
		user, err := r.userByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, user)
	case groupResourceKind:
		group, err := r.groupByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, group)
	default:
		return errors.NewCode(errors.InvalidInput, "unsupported related resource kind").
			WithContext("kind", kind)
	}
}

func (r *RoleRepo) userRoleBindingModel(ctx context.Context) (orm.IModel, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.UserRoleBinding](),
		Table:        "user_role_bindings",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 user_role_bindings 模型失败")
	}
	return model, nil
}

func (r *RoleRepo) groupByID(ctx context.Context, groupID int64) (*iamentity.Group, error) {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Group](),
		Table:        "groups",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 groups 模型失败")
	}
	var group iamentity.Group
	if err := model.First(ctx, &group,
		orm.WithWhere("id = ?", groupID),
		orm.WithWhere("tenant_id = ?", tenantID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "组织不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询组织失败")
	}
	return &group, nil
}

func requireSpecMatch(s spec.Spec, entity any) error {
	if s.Err() != nil {
		return s.Err()
	}
	ok, err := spec.NewInterpreter().Match(s, entity)
	if err != nil {
		return err
	}
	if !ok {
		return errors.NewCode(errors.Forbidden, "entity does not satisfy the required scope")
	}
	return nil
}

// CountByStatus 统计各状态角色数量。
func (r *RoleRepo) CountByStatus(ctx context.Context, s spec.Spec) (map[string]int64, error) {
	statusMap := make(map[string]int64)
	const pageSize = 1000
	for offset := 0; ; offset += pageSize {
		// 只统计 id/status 投影，绕过 Query 覆盖以跳过关联补齐。
		roles, err := r.Repo.Query(ctx, query.QueryOptions{
			Offset: offset,
			Limit:  pageSize,
			Fields: []string{"id", "status"},
		}, s)
		if err != nil {
			return nil, errors.Wrap(err, errors.Database, "统计角色状态失败")
		}
		for _, role := range roles {
			if role != nil {
				statusMap[role.Status]++
			}
		}
		if len(roles) < pageSize {
			return statusMap, nil
		}
	}
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
			orm.WithSelect("role_id"),
			orm.WithSelectExprUnsafe("COUNT(*) as count"),
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
			orm.WithSelect("role_id"),
			orm.WithSelectExprUnsafe("COUNT(*) as count"),
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
func (r *RoleRepo) SearchRoles(ctx context.Context, keyword string, limit int, condition spec.Spec) ([]*iamentity.Role, error) {
	var roles []*iamentity.Role
	query, err := r.ScopedQueryWithSpec(ctx, condition)
	if err != nil {
		return nil, err
	}
	if keyword != "" {
		pattern := likesafe.ContainsPattern(keyword)
		query.Where("(name LIKE ?"+likesafe.EscapeClause+" OR description LIKE ?"+likesafe.EscapeClause+")", pattern, pattern)
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
func (r *RoleRepo) InitializeSystemRoles(ctx context.Context, conditions ...spec.Spec) error {
	guard := spec.All()
	if len(conditions) > 0 {
		guard = spec.And(conditions...)
	}
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
			if err := r.Create(ctx, &clone, guard); err != nil {
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

	scopeIDs := make([]int64, 0, len(roles))
	seenScopeIDs := make(map[int64]struct{}, len(roles))
	for _, role := range roles {
		if role == nil || role.NamespaceScopeID <= 0 {
			continue
		}
		if _, ok := seenScopeIDs[role.NamespaceScopeID]; ok {
			continue
		}
		seenScopeIDs[role.NamespaceScopeID] = struct{}{}
		scopeIDs = append(scopeIDs, role.NamespaceScopeID)
	}
	if len(scopeIDs) == 0 {
		return roles, nil
	}
	var scopes []*iamentity.Scope
	if err := scopeModel.Find(ctx, &scopes, orm.WithWhere("id IN ? AND deleted_at IS NULL", scopeIDs)); err != nil {
		return nil, errors.Wrap(err, errors.Database, "批量查询 namespace scope 失败")
	}
	scopeByID := make(map[int64]*iamentity.Scope, len(scopes))
	for _, scope := range scopes {
		if scope != nil {
			scopeByID[scope.GetID()] = scope
		}
	}
	for _, role := range roles {
		if role != nil {
			role.NamespaceScope = scopeByID[role.NamespaceScopeID]
		}
	}
	return roles, nil
}

func tenantOwnerID(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return "tenant:" + tenantID
}

func (r *RoleRepo) userByID(ctx context.Context, userID int64) (*iamentity.User, error) {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.User](),
		Table:        "users",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 user 模型失败")
	}
	var user iamentity.User
	if err := model.First(ctx, &user,
		orm.WithWhere("id = ?", userID),
		orm.WithWhere("tenant_id = ?", tenantID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "用户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询用户失败")
	}
	return &user, nil
}
