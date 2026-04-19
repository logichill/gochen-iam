package group

import (
	"context"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	"gochen/app/access"
	"gochen/auth"
	"gochen/db/orm"
	"gochen/db/orm/repo"
	"gochen/domain/crud"
	"gochen/errors"
	"gochen/ident"
)

// GroupRepo 组织数据访问层
type GroupRepo struct {
	*repo.Repo[*iamentity.Group, int64]
}

const (
	groupResourceKind = "iam.group"
	userResourceKind  = "iam.user"
	roleResourceKind  = "iam.role"
)

func (r *GroupRepo) tenantScopedQuery(ctx context.Context) (*repo.ScopedQuery, error) {
	query, err := r.Repo.ScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	tenantID, err := crud.ResolveTenantID(ctx)
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
func NewGroupRepository(o orm.IOrm) (*GroupRepo, error) {
	base, err := repo.NewRepo(
		o,
		"groups",
		repo.WithIDGenerator[*iamentity.Group](ident.DefaultInt64Generator()),
		repo.WithResourceKind[*iamentity.Group, int64]("iam.group"),
		repo.WithSoftDeleteColumns[*iamentity.Group, int64]("deleted_at", ""),
		repo.WithAccessColumns[*iamentity.Group, int64]("managed_scope_id", "owner_id", "version"),
	)
	if err != nil {
		return nil, err
	}
	return &GroupRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 创建组织，并在同一事务内补齐 path/level 派生字段。
func (r *GroupRepo) Create(ctx context.Context, group *iamentity.Group) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = managedScopeFromContext(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	txCtx, err := r.BeginTx(ctx)
	if err != nil {
		return err
	}
	txContext := txCtx.Context()
	committed := false
	defer func() {
		if !committed {
			_ = r.Rollback(txCtx)
		}
	}()

	if err := r.syncGroupHierarchy(txContext, group); err != nil {
		return err
	}
	if err := r.Repo.Create(txContext, group); err != nil {
		return err
	}
	if err := r.syncGroupHierarchy(txContext, group); err != nil {
		return err
	}
	if err := r.Repo.Update(txContext, group); err != nil {
		return err
	}
	if err := r.Commit(txCtx); err != nil {
		return err
	}
	committed = true
	return nil
}

// Update 更新组织，并在父链变化时同步修复整个子树的 path/level。
func (r *GroupRepo) Update(ctx context.Context, group *iamentity.Group) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = managedScopeFromContext(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	txCtx, err := r.BeginTx(ctx)
	if err != nil {
		return err
	}
	txContext := txCtx.Context()
	committed := false
	defer func() {
		if !committed {
			_ = r.Rollback(txCtx)
		}
	}()

	current, err := r.Get(txContext, group.GetID())
	if err != nil {
		return err
	}
	if err := r.syncGroupHierarchy(txContext, group); err != nil {
		return err
	}
	pathChanged := current.Path != group.Path || current.Level != group.Level || int64PtrValue(current.ParentID) != int64PtrValue(group.ParentID)

	if err := r.Repo.Update(txContext, group); err != nil {
		return err
	}
	if pathChanged {
		if err := r.repairDescendantHierarchy(txContext, group, func(child *iamentity.Group) error {
			return r.Repo.Update(txContext, child)
		}); err != nil {
			return err
		}
	}
	if err := r.Commit(txCtx); err != nil {
		return err
	}
	committed = true
	return nil
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

// CreateWithConstraint 在显式写边界下创建组织，并在同一事务内修复派生层级字段。
func (r *GroupRepo) CreateWithConstraint(ctx context.Context, group *iamentity.Group, guard iamaccess.WriteConstraint) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if err := r.Repo.EnsureID(group); err != nil {
		return err
	}
	txCtx, err := r.BeginTx(ctx)
	if err != nil {
		return err
	}
	txContext := txCtx.Context()
	committed := false
	defer func() {
		if !committed {
			_ = r.Rollback(txCtx)
		}
	}()

	if err := r.syncGroupHierarchy(txContext, group); err != nil {
		return err
	}
	if err := r.Repo.CreateWithConstraint(assocguard.BindContext(txContext, guard), group, guard.Unwrap()); err != nil {
		return err
	}
	if err := r.Commit(txCtx); err != nil {
		return err
	}
	committed = true
	return nil
}

// UpdateWithConstraint 在显式写边界下更新组织，并在父链变化时同步修复子树。
func (r *GroupRepo) UpdateWithConstraint(ctx context.Context, group *iamentity.Group, guard iamaccess.WriteConstraint) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	txCtx, err := r.BeginTx(ctx)
	if err != nil {
		return err
	}
	txContext := txCtx.Context()
	committed := false
	defer func() {
		if !committed {
			_ = r.Rollback(txCtx)
		}
	}()

	current, err := r.Get(txContext, group.GetID())
	if err != nil {
		return err
	}
	if err := r.syncGroupHierarchy(txContext, group); err != nil {
		return err
	}
	pathChanged := current.Path != group.Path || current.Level != group.Level || int64PtrValue(current.ParentID) != int64PtrValue(group.ParentID)

	if err := r.Repo.UpdateWithConstraint(assocguard.BindContext(txContext, guard), group, guard.Unwrap()); err != nil {
		return err
	}
	if pathChanged {
		if err := r.repairDescendantHierarchy(txContext, group, func(child *iamentity.Group) error {
			return r.Repo.UpdateWithConstraint(assocguard.BindContext(txContext, guard), child, guard.Unwrap())
		}); err != nil {
			return err
		}
	}
	if err := r.Commit(txCtx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (r *GroupRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
}

func (r *GroupRepo) syncGroupHierarchy(ctx context.Context, group *iamentity.Group) error {
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
		parent, err = r.Get(ctx, *group.ParentID)
		if err != nil {
			return errors.Wrap(err, errors.NotFound, "父组织不存在")
		}
	}
	group.SetParent(parent)
	return nil
}

// Get 根据ID获取组织。
func (r *GroupRepo) Get(ctx context.Context, id int64) (*iamentity.Group, error) {
	group, err := r.getByID(ctx, id)
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

// AddUserToGroup 将用户添加到组织
func (r *GroupRepo) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	// 检查组织是否存在
	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(group, "Users").
		Append(ctx, &iamentity.User{Entity: crud.Entity[int64]{ID: userID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "添加用户到组织失败")
	}

	return nil
}

// AddUserToGroupWithConstraint 在显式多资源写边界下把用户加入组织。
func (r *GroupRepo) AddUserToGroupWithConstraint(ctx context.Context, groupID, userID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateGroupAssociationWithConstraint(
		ctx,
		groupID,
		"Users",
		userResourceKind,
		userID,
		&iamentity.User{Entity: crud.Entity[int64]{ID: userID}},
		false,
		"添加用户到组织失败",
		guard,
	)
}

// RemoveUserFromGroup 从组织中移除用户
func (r *GroupRepo) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	// 检查组织是否存在
	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(group, "Users").
		Delete(ctx, &iamentity.User{Entity: crud.Entity[int64]{ID: userID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "从组织移除用户失败")
	}

	return nil
}

// RemoveUserFromGroupWithConstraint 在显式多资源写边界下把用户移出组织。
func (r *GroupRepo) RemoveUserFromGroupWithConstraint(ctx context.Context, groupID, userID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateGroupAssociationWithConstraint(
		ctx,
		groupID,
		"Users",
		userResourceKind,
		userID,
		&iamentity.User{Entity: crud.Entity[int64]{ID: userID}},
		true,
		"从组织移除用户失败",
		guard,
	)
}

// AddDefaultRole 为组织添加默认角色
func (r *GroupRepo) AddDefaultRole(ctx context.Context, groupID, roleID int64) error {
	// 检查组织是否存在
	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(group, "DefaultRoles").
		Append(ctx, &iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "添加默认角色失败")
	}

	return nil
}

// AddDefaultRoleWithConstraint 在显式多资源写边界下给组织添加默认角色。
func (r *GroupRepo) AddDefaultRoleWithConstraint(ctx context.Context, groupID, roleID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateGroupAssociationWithConstraint(
		ctx,
		groupID,
		"DefaultRoles",
		roleResourceKind,
		roleID,
		&iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}},
		false,
		"添加默认角色失败",
		guard,
	)
}

// RemoveDefaultRole 移除组织的默认角色
func (r *GroupRepo) RemoveDefaultRole(ctx context.Context, groupID, roleID int64) error {
	// 检查组织是否存在
	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(group, "DefaultRoles").
		Delete(ctx, &iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}})

	if err != nil {
		return errors.Wrap(err, errors.Database, "移除默认角色失败")
	}

	return nil
}

// RemoveDefaultRoleWithConstraint 在显式多资源写边界下移除组织默认角色。
func (r *GroupRepo) RemoveDefaultRoleWithConstraint(ctx context.Context, groupID, roleID int64, guard iamaccess.WriteConstraint) error {
	return r.mutateGroupAssociationWithConstraint(
		ctx,
		groupID,
		"DefaultRoles",
		roleResourceKind,
		roleID,
		&iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}},
		true,
		"移除默认角色失败",
		guard,
	)
}

func (r *GroupRepo) mutateGroupAssociationWithConstraint(
	ctx context.Context,
	groupID int64,
	association string,
	relatedKind string,
	relatedID int64,
	related any,
	remove bool,
	message string,
	guard iamaccess.WriteConstraint,
) error {
	if _, _, err := assocguard.RequirePair(guard, groupResourceKind, groupID, relatedKind, relatedID); err != nil {
		return err
	}

	group, err := r.getByID(ctx, groupID)
	if err != nil {
		return err
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}

	associationRef := model.Association(group, association)
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
func (r *GroupRepo) CountByLevel(ctx context.Context) (map[int]int64, error) {
	type LevelCount struct {
		Level int   `json:"level"`
		Count int64 `json:"count"`
	}

	var results []LevelCount
	query, err := r.tenantScopedQuery(ctx)
	if err != nil {
		return nil, err
	}
	err = query.
		Select("level", "COUNT(*) as count").
		GroupBy("level").
		Find(&results)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "统计组织层级失败")
	}

	levelMap := make(map[int]int64)
	for _, result := range results {
		levelMap[result.Level] = result.Count
	}

	return levelMap, nil
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
		query.Where("name LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
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
