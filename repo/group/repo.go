package group

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen-iam/repo/internal/likesafe"
	scoperesolver "gochen-iam/repo/internal/scope"
	"gochen-iam/repo/relations"
	iamtenant "gochen-iam/tenant"
	"gochen-runtime/db/orm/repo"
	"gochen/app/query"
	"gochen/db/orm"
	domaincrud "gochen/domain/crud"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/gen"
)

// GroupRepo 组织数据访问层
type GroupRepo struct {
	*repo.Repo[*iamentity.Group, int64]
}

const (
	userResourceKind = "iam.user"
	roleResourceKind = "iam.role"
)

func (r *GroupRepo) tenantScopedQuery(ctx context.Context) (*repo.ScopedQuery, error) {
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

func (r *GroupRepo) findOne(ctx context.Context, configure func(*repo.ScopedQuery)) (*iamentity.Group, error) {
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	if configure != nil {
		configure(query)
	}
	var group *iamentity.Group
	if err := query.First(&group); err != nil {
		return nil, err
	}
	return group, nil
}

func (r *GroupRepo) getByID(ctx context.Context, id int64) (*iamentity.Group, error) {
	return r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("id = ?", id)
	})
}

// NewGroupRepository 创建分组仓储。
func NewGroupRepository(o orm.IOrm, idGenerator gen.IGenerator[int64]) (*GroupRepo, error) {
	base, err := repo.NewRepo[*iamentity.Group, int64](
		o,
		"groups",
		repo.WithIDGenerator[*iamentity.Group, int64](idGenerator),
		repo.WithResourceKind[*iamentity.Group, int64]("iam.group"),
		repo.WithSoftDeleteColumns[*iamentity.Group, int64]("deleted_at", ""),
		repo.WithIsolation[*iamentity.Group, int64](repo.IsolationCols{Column: "tenant_id"}),
	)
	if err != nil {
		return nil, err
	}
	return &GroupRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 预分配组织 ID，并在同一事务内写入完整的 path/level 派生字段。
func (r *GroupRepo) Create(ctx context.Context, group *iamentity.Group, s spec.Spec) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if err := r.EnsureID(group); err != nil {
		return err
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		if err := r.syncGroupHierarchy(txCtx, group, s); err != nil {
			return err
		}
		return r.Repo.Create(txCtx, group, s)
	})
}

// Update 更新组织，并在父链变化时同步修复整个子树的 path/level。
func (r *GroupRepo) Update(ctx context.Context, group *iamentity.Group, s spec.Spec) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		current, err := r.Get(txCtx, group.GetID(), s)
		if err != nil {
			return err
		}
		if err := r.syncGroupHierarchy(txCtx, group, s); err != nil {
			return err
		}
		pathChanged := current.Path != group.Path || current.Level != group.Level || int64PtrValue(current.ParentID) != int64PtrValue(group.ParentID)

		updated := groupWithoutAssociations(group)
		if err := r.Repo.Update(txCtx, updated, s); err != nil {
			return err
		}
		group.Version = updated.GetVersion()
		group.SetUpdatedAt(updated.GetUpdatedAt())
		if pathChanged {
			if err := r.repairDescendantHierarchy(txCtx, group, func(child *iamentity.Group) error {
				return r.Repo.Update(txCtx, child, s)
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Delete 执行软删除并保留 IAM 既有语义；物理删除请使用 Purge。
func (r *GroupRepo) Delete(ctx context.Context, group *iamentity.Group, s spec.Spec) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.IsDeleted() {
		return errors.NewCode(errors.Conflict, "组织已删除").WithContext("id", group.GetID())
	}
	group.MarkAsDeleted()
	return r.Repo.Update(ctx, groupWithoutAssociations(group), s)
}

func groupWithoutAssociations(group *iamentity.Group) *iamentity.Group {
	if group == nil {
		return nil
	}
	clone := *group
	clone.Parent = nil
	clone.Children = nil
	clone.Users = nil
	clone.DefaultRoles = nil
	return &clone
}

func (r *GroupRepo) CountByManagedScopeID(ctx context.Context, scopeID int64) (int64, error) {
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.Group](),
		Table:        "groups",
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "初始化 groups 模型失败")
	}
	count, err := model.Count(ctx,
		orm.WithWhere("managed_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计组织 managed scope 引用失败")
	}
	return count, nil
}

func tenantOwnerID(tenantID string) string {
	if tenantID == "" {
		return ""
	}
	return "tenant:" + tenantID
}

func (r *GroupRepo) syncGroupHierarchy(ctx context.Context, group *iamentity.Group, s spec.Spec) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ParentID == nil {
		group.SetParent(nil)
		return nil
	}

	parent := group.Parent
	if parent == nil || parent.GetID() != *group.ParentID {
		var err error
		parent, err = r.Get(ctx, *group.ParentID, s)
		if err != nil {
			return errors.Wrap(err, errors.NotFound, "父组织不存在")
		}
	}
	group.SetParent(parent)
	return nil
}

// Get 根据ID获取组织。
func (r *GroupRepo) Get(ctx context.Context, id int64, s spec.Spec) (*iamentity.Group, error) {
	group, err := r.Repo.Get(ctx, id, s)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "组织不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询组织失败")
	}
	return group, nil
}

// FindByUserID 根据用户ID查找所属组织。
func (r *GroupRepo) FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Join(orm.InnerJoin("user_groups", "", orm.On("groups.id", "user_groups.group_id"))).
		Where("user_groups.user_id = ?", userID).
		Preload("Parent", "DefaultRoles", "Users").
		Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询用户组织失败")
	}

	return groups, nil
}

// FindChildren 查找子组织。
func (r *GroupRepo) FindChildren(ctx context.Context, parentID int64) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Where("parent_id = ?", parentID).
		Preload("Users", "DefaultRoles").
		Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询子组织失败")
	}

	return groups, nil
}

// FindRootGroups 查找根组织（没有父组织的组织）。
func (r *GroupRepo) FindRootGroups(ctx context.Context) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Where("parent_id IS NULL").
		Preload("Children", "Users", "DefaultRoles").
		Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询根组织失败")
	}

	return groups, nil
}

// FindByLevel 根据层级查找组织。
func (r *GroupRepo) FindByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Where("level = ?", level).
		Preload("Parent", "Users").
		Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询组织失败")
	}

	return groups, nil
}

// FindByPath 根据路径查找组织
func (r *GroupRepo) FindByPath(ctx context.Context, path string) (*iamentity.Group, error) {
	group, err := r.findOne(ctx, func(q *repo.ScopedQuery) {
		q.Where("path = ?", path).
			Preload("Parent", "Children", "Users", "DefaultRoles")
	})
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "组织不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询组织失败")
	}
	return group, nil
}

// FindAncestors 查找祖先组织
func (r *GroupRepo) FindAncestors(ctx context.Context, groupID int64) ([]*iamentity.Group, error) {
	// 首先获取当前组织
	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return nil, err
	}

	var ancestors []*iamentity.Group
	currentGroup := *group // 解引用

	// 向上遍历找到所有祖先
	for currentGroup.ParentID != nil {
		parent, err := r.getByID(ctx, *currentGroup.ParentID)
		if err != nil {
			break // 如果找不到父组织，停止查找
		}
		ancestors = append([]*iamentity.Group{parent}, ancestors...) // 插入到开头，解引用
		currentGroup = *parent                                       // 解引用
	}

	return ancestors, nil
}

// FindDescendants 查找所有后代组织。
func (r *GroupRepo) FindDescendants(ctx context.Context, groupID int64) ([]*iamentity.Group, error) {
	var descendants []*iamentity.Group

	// 递归查找所有后代
	err := r.findDescendantsRecursive(ctx, groupID, &descendants)
	if err != nil {
		return nil, err
	}

	return descendants, nil
}

// findDescendantsRecursive 递归查找后代组织。
func (r *GroupRepo) findDescendantsRecursive(ctx context.Context, parentID int64, descendants *[]*iamentity.Group) error {
	children, err := r.FindChildren(ctx, parentID)
	if err != nil {
		return err
	}

	for _, child := range children {
		*descendants = append(*descendants, child)
		// 递归查找子组织的后代
		err := r.findDescendantsRecursive(ctx, child.GetID(), descendants)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *GroupRepo) repairDescendantHierarchy(
	ctx context.Context,
	parent *iamentity.Group,
	updateChild func(*iamentity.Group) error,
) error {
	children, err := r.FindChildren(ctx, parent.GetID())
	if err != nil {
		return err
	}
	for _, child := range children {
		child.SetParent(parent)
		if child.Level > 10 {
			return errors.NewCode(errors.Validation, "组织层级不能超过10级")
		}
		if err := updateChild(child); err != nil {
			return err
		}
		if err := r.repairDescendantHierarchy(ctx, child, updateChild); err != nil {
			return err
		}
	}
	return nil
}

func int64PtrValue(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func (r *GroupRepo) GroupsForUsers(ctx context.Context, userIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
	return relations.Read(ctx, r.Repo, userIDs, condition, orm.InnerJoin("user_groups", "", orm.On("groups.id", "user_groups.group_id")), "user_groups.user_id", "groups.id")
}

// AddUserToGroup 将用户添加到组织
func (r *GroupRepo) AddUserToGroup(ctx context.Context, groupID, userID int64, groupSpec, userSpec spec.Spec) error {
	return r.mutateGroupAssociation(ctx, groupID, "Users", userResourceKind, userID,
		&iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}}, false, "添加用户到组织失败", groupSpec, userSpec)
}

// RemoveUserFromGroup 从组织中移除用户
func (r *GroupRepo) RemoveUserFromGroup(ctx context.Context, groupID, userID int64, groupSpec, userSpec spec.Spec) error {
	return r.mutateGroupAssociation(ctx, groupID, "Users", userResourceKind, userID,
		&iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}}, true, "从组织移除用户失败", groupSpec, userSpec)
}

// AddDefaultRole 为组织添加默认角色
func (r *GroupRepo) AddDefaultRole(ctx context.Context, groupID, roleID int64, groupSpec, roleSpec spec.Spec) error {
	return r.mutateGroupAssociation(ctx, groupID, "DefaultRoles", roleResourceKind, roleID,
		&iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}}, false, "添加默认角色失败", groupSpec, roleSpec)
}

// RemoveDefaultRole 移除组织的默认角色
func (r *GroupRepo) RemoveDefaultRole(ctx context.Context, groupID, roleID int64, groupSpec, roleSpec spec.Spec) error {
	return r.mutateGroupAssociation(ctx, groupID, "DefaultRoles", roleResourceKind, roleID,
		&iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}}, true, "移除默认角色失败", groupSpec, roleSpec)
}

func (r *GroupRepo) mutateGroupAssociation(
	ctx context.Context,
	groupID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	groupSpec, relatedSpec spec.Spec,
) error {
	return r.WithinTx(ctx, func(txCtx context.Context) error {
		group, err := r.Repo.Get(txCtx, groupID, groupSpec)
		if err != nil {
			return err
		}
		if err := r.requireRelatedInSpec(txCtx, relatedKind, relatedID, relatedSpec); err != nil {
			return err
		}
		model, err := r.ModelFor(txCtx)
		if err != nil {
			return err
		}

		associationRef := model.Association(group, association)
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

func (r *GroupRepo) requireRelatedInSpec(ctx context.Context, kind string, id int64, s spec.Spec) error {
	switch kind {
	case userResourceKind:
		user, err := r.userByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, user)
	case roleResourceKind:
		role, err := r.roleByID(ctx, id)
		if err != nil {
			return err
		}
		return requireSpecMatch(s, role)
	default:
		return errors.NewCode(errors.InvalidInput, "unsupported related resource kind").
			WithContext("kind", kind)
	}
}

func (r *GroupRepo) userByID(ctx context.Context, userID int64) (*iamentity.User, error) {
	return firstTenantEntity[iamentity.User](ctx, r.Orm(), "users", userID, "用户不存在", "查询用户失败")
}

func (r *GroupRepo) roleByID(ctx context.Context, roleID int64) (*iamentity.Role, error) {
	return firstTenantEntity[iamentity.Role](ctx, r.Orm(), "roles", roleID, "角色不存在", "查询角色失败")
}

func firstTenantEntity[T any](ctx context.Context, engine orm.IOrm, table string, id int64, notFoundMsg, queryMsg string) (*T, error) {
	tenantID, err := (iamtenant.Resolver{}).ResolveTenantID(ctx)
	if err != nil {
		return nil, err
	}
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[T](),
		Table:        table,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 "+table+" 模型失败")
	}
	var entity T
	if err := model.First(ctx, &entity,
		orm.WithWhere("id = ?", id),
		orm.WithWhere("tenant_id = ?", tenantID),
		orm.WithWhere("deleted_at IS NULL"),
	); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, notFoundMsg)
		}
		return nil, errors.Wrap(err, errors.Database, queryMsg)
	}
	return &entity, nil
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

// GroupTree 获取组织树结构。
func (r *GroupRepo) GroupTree(ctx context.Context) ([]*iamentity.Group, error) {
	var allGroups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Preload("Users", "DefaultRoles").
		Order("level", false).
		Order("name", false).
		Find(&allGroups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询组织树失败")
	}

	// 构建树结构
	groupMap := make(map[int64]*iamentity.Group)
	var rootGroups []*iamentity.Group

	// 第一遍：创建映射
	for _, group := range allGroups {
		groupMap[group.GetID()] = group
		group.Children = []*iamentity.Group{} // 初始化子组织切片
	}

	// 第二遍：构建父子关系
	for _, group := range allGroups {
		if group.ParentID == nil {
			rootGroups = append(rootGroups, group)
		} else {
			if parent, exists := groupMap[*group.ParentID]; exists {
				parent.Children = append(parent.Children, group)
			}
		}
	}

	return rootGroups, nil
}

// CountByLevel 统计各层级组织数量。
func (r *GroupRepo) CountByLevel(ctx context.Context, s spec.Spec) (map[int]int64, error) {
	levelMap := make(map[int]int64)
	const pageSize = 1000
	for offset := 0; ; offset += pageSize {
		groups, err := r.Query(ctx, query.QueryOptions{
			Offset: offset,
			Limit:  pageSize,
			Fields: []string{"id", "level"},
		}, s)
		if err != nil {
			return nil, errors.Wrap(err, errors.Database, "统计组织层级失败")
		}
		for _, group := range groups {
			if group != nil {
				levelMap[group.Level]++
			}
		}
		if len(groups) < pageSize {
			return levelMap, nil
		}
	}
}

// SearchGroups 搜索组织（支持名称模糊搜索）。
func (r *GroupRepo) SearchGroups(ctx context.Context, keyword string, limit int) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	query.Preload("Parent", "Users")
	if keyword != "" {
		pattern := likesafe.ContainsPattern(keyword)
		query.Where("(name LIKE ?"+likesafe.EscapeClause+" OR description LIKE ?"+likesafe.EscapeClause+")", pattern, pattern)
	}
	if limit > 0 {
		query.Limit(limit)
	}
	err = query.Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "搜索组织失败")
	}

	return groups, nil
}

// GroupsForRoles 以独立条件读取已授权角色关联的组织聚合。
func (r *GroupRepo) GroupsForRoles(ctx context.Context, roleIDs []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
	return relations.Read(ctx, r.Repo, roleIDs, condition, orm.InnerJoin("group_roles", "", orm.On("groups.id", "group_roles.group_id")), "group_roles.role_id", "groups.id")
}

// FindByDefaultRoleID 根据默认角色ID查找组织。
func (r *GroupRepo) FindByDefaultRoleID(ctx context.Context, roleID int64) ([]*iamentity.Group, error) {
	var groups []*iamentity.Group
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Join(orm.InnerJoin("group_roles", "", orm.On("groups.id", "group_roles.group_id"))).
		Where("group_roles.role_id = ?", roleID).
		Preload("Parent", "Users", "DefaultRoles").
		Find(&groups)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询使用指定默认角色的组织失败")
	}

	return groups, nil
}
