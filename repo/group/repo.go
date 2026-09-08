package group

import (
	"context"

	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	scoperesolver "gochen-iam/repo/internal/scope"
	iamtenant "gochen-iam/tenant"
	"gochen-runtime/db/orm/repo"
	appcrud "gochen/app/crud"
	"gochen/auth/scoped"
	"gochen/db/orm"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
	"gochen/gen"
	"strconv"
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
		repo.WithScope[*iamentity.Group, int64](repo.ScopeCols{ManagedScopeID: "managed_scope_id", OwnerID: "owner_id", Revision: "version"}),
		repo.WithDataScopeResolver[*iamentity.Group, int64](scoperesolver.DefaultResolver),
	)
	if err != nil {
		return nil, err
	}
	return &GroupRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 预分配组织 ID，并在同一事务内写入完整的 path/level 派生字段。
func (r *GroupRepo) Create(ctx context.Context, group *iamentity.Group) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if err := r.Repo.EnsureID(group); err != nil {
		return err
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	return appcrud.WithTx(ctx, r.Repo, func(txCtx context.Context) error {
		if err := r.syncGroupHierarchy(txCtx, group); err != nil {
			return err
		}
		return r.Repo.Create(txCtx, group)
	})
}

// Update 更新组织，并在父链变化时同步修复整个子树的 path/level。
func (r *GroupRepo) Update(ctx context.Context, group *iamentity.Group) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if group.ManagedScopeID == 0 {
		group.ManagedScopeID = scoperesolver.ResolveManagedScopeID(ctx)
	}
	if group.OwnerID == "" {
		group.OwnerID = tenantOwnerID(group.TenantID)
	}
	return appcrud.WithTx(ctx, r.Repo, func(txCtx context.Context) error {
		current, err := r.Get(txCtx, group.GetID())
		if err != nil {
			return err
		}
		if err := r.syncGroupHierarchy(txCtx, group); err != nil {
			return err
		}
		pathChanged := current.Path != group.Path || current.Level != group.Level || int64PtrValue(current.ParentID) != int64PtrValue(group.ParentID)

		updated := groupWithoutAssociations(group)
		if err := r.Repo.Update(txCtx, updated); err != nil {
			return err
		}
		group.Version = updated.GetVersion()
		group.SetUpdatedAt(updated.GetUpdatedAt())
		if pathChanged {
			if err := r.repairDescendantHierarchy(txCtx, group, func(child *iamentity.Group) error {
				childCtx, err := r.derivedGroupConstraintCtx(txCtx, group.GetID(), child)
				if err != nil {
					return err
				}
				return r.Repo.Update(childCtx, child)
			}); err != nil {
				return err
			}
		}
		return nil
	})
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

// CreateWithConstraint 在显式写边界下创建组织，并在同一事务内修复派生层级字段。
func (r *GroupRepo) CreateWithConstraint(ctx context.Context, group *iamentity.Group, guard iamaccess.WriteConstraint) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	if err := r.Repo.EnsureID(group); err != nil {
		return err
	}
	return appcrud.WithTx(ctx, r.Repo, func(txCtx context.Context) error {
		if err := r.syncGroupHierarchy(txCtx, group); err != nil {
			return err
		}
		boundCtx := r.boundContext(txCtx, guard)
		return r.Repo.Create(boundCtx, group)
	})
}

// UpdateWithConstraint 在显式写边界下更新组织，并在父链变化时同步修复子树。
func (r *GroupRepo) UpdateWithConstraint(ctx context.Context, group *iamentity.Group, guard iamaccess.WriteConstraint) (err error) {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "group cannot be nil")
	}
	return appcrud.WithTx(ctx, r.Repo, func(txCtx context.Context) error {
		current, err := r.Get(txCtx, group.GetID())
		if err != nil {
			return err
		}
		if err := r.syncGroupHierarchy(txCtx, group); err != nil {
			return err
		}
		pathChanged := current.Path != group.Path || current.Level != group.Level || int64PtrValue(current.ParentID) != int64PtrValue(group.ParentID)

		boundCtx := r.boundContext(txCtx, guard)
		if err := r.Repo.Update(boundCtx, group); err != nil {
			return err
		}
		if pathChanged {
			if err := r.repairDescendantHierarchy(txCtx, group, func(child *iamentity.Group) error {
				childBoundCtx := r.boundContext(txCtx, guard)
				return r.Repo.Update(childBoundCtx, child)
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *GroupRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	boundCtx := r.boundContext(ctx, guard)
	return r.Repo.Delete(boundCtx, id)
}

func (r *GroupRepo) boundContext(ctx context.Context, guard iamaccess.WriteConstraint) context.Context {
	return scoped.WithConstraint(assocguard.BindContext(ctx, guard), scoped.SingleEntityConstraint(r.ResourceKind(), guard.Unwrap()))
}

// derivedGroupConstraintCtx 为创建后的层级补齐及同范围子树修复绑定真实版本。
// 显式授权过的子节点保留原快照；从父节点派生时不得扩张租户或 managed scope。
func (r *GroupRepo) derivedGroupConstraintCtx(ctx context.Context, parentID int64, group *iamentity.Group) (context.Context, error) {
	constraint, ok := scoped.ConstraintFrom(ctx, r.ResourceKind())
	if !ok {
		return nil, errors.NewCode(errors.Forbidden, "group hierarchy write constraint is required")
	}
	id := strconv.FormatInt(group.GetID(), 10)
	for _, resource := range constraint.Resources {
		if resource.Kind == r.ResourceKind() && resource.ResourceID == id {
			return ctx, nil
		}
	}
	resource, err := constraint.RequireResource(r.ResourceKind(), strconv.FormatInt(parentID, 10))
	if err != nil {
		return nil, err
	}
	if resource.TenantID != group.TenantID || resource.ManagedScopeID != group.ManagedScopeID {
		return nil, errors.NewCode(errors.Forbidden, "group hierarchy repair exceeds authorized boundary")
	}
	resource.ResourceID = id
	resource.Revision = strconv.FormatUint(group.GetVersion(), 10)
	return scoped.WithConstraint(ctx, scoped.SingleEntityConstraint(r.ResourceKind(), scoped.WriteConstraint{
		Resources: []scoped.ResourceConstraint{resource},
	})), nil
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
		Append(ctx, &iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}})

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
		&iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}},
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
		Delete(ctx, &iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}})

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
		&iamentity.User{Entity: domaincrud.Entity[int64]{ID: userID}},
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
		Append(ctx, &iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}})

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
		&iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}},
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
		Delete(ctx, &iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}})

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
		&iamentity.Role{Entity: domaincrud.Entity[int64]{ID: roleID}},
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
