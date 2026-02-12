package group

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/domain/crud"
	"gochen/errorx"
	"gochen/ident/generator"
)

// GroupRepo 组织数据访问层
type GroupRepo struct {
	*db.Repo[*iamentity.Group, int64]
}

// NewGroupRepository 创建组织Repository
func NewGroupRepository(o orm.IOrm) (*GroupRepo, error) {
	base, err := db.NewRepo(
		o,
		"groups",
		db.WithIDGenerator[*iamentity.Group](generator.DefaultInt64Generator()),
	)
	if err != nil {
		return nil, err
	}
	return &GroupRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// GetByID 根据ID获取组织（过滤软删记录）
func (r *GroupRepo) GetByID(ctx context.Context, id int64) (*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var group iamentity.Group
	err = model.First(ctx, &group, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "组织不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询组织失败")
	}
	return &group, nil
}

// FindByUserID 根据用户ID查找所属组织
func (r *GroupRepo) FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	err = model.Find(ctx, &groups,
		orm.WithJoin(orm.InnerJoin("user_groups", "", orm.On("groups.id", "user_groups.group_id"))),
		orm.WithWhere("user_groups.user_id = ? AND groups.deleted_at IS NULL", userID),
		orm.WithPreload("Parent"),
		orm.WithPreload("DefaultRoles"),
		orm.WithPreload("Users"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询用户组织失败")
	}

	return groups, nil
}

// FindChildren 查找子组织
func (r *GroupRepo) FindChildren(ctx context.Context, parentID int64) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	err = model.Find(ctx, &groups,
		orm.WithWhere("parent_id = ? AND deleted_at IS NULL", parentID),
		orm.WithPreload("Users"),
		orm.WithPreload("DefaultRoles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询子组织失败")
	}

	return groups, nil
}

// FindRootGroups 查找根组织（没有父组织的组织）
func (r *GroupRepo) FindRootGroups(ctx context.Context) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	err = model.Find(ctx, &groups,
		orm.WithWhere("parent_id IS NULL AND deleted_at IS NULL"),
		orm.WithPreload("Children"),
		orm.WithPreload("Users"),
		orm.WithPreload("DefaultRoles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询根组织失败")
	}

	return groups, nil
}

// FindByLevel 根据层级查找组织
func (r *GroupRepo) FindByLevel(ctx context.Context, level int) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	err = model.Find(ctx, &groups,
		orm.WithWhere("level = ? AND deleted_at IS NULL", level),
		orm.WithPreload("Parent"),
		orm.WithPreload("Users"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询组织失败")
	}

	return groups, nil
}

// FindByPath 根据路径查找组织
func (r *GroupRepo) FindByPath(ctx context.Context, path string) (*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var group iamentity.Group
	err = model.First(ctx, &group,
		orm.WithWhere("path = ? AND deleted_at IS NULL", path),
		orm.WithPreload("Parent"),
		orm.WithPreload("Children"),
		orm.WithPreload("Users"),
		orm.WithPreload("DefaultRoles"),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "组织不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询组织失败")
	}

	return &group, nil
}

// FindAncestors 查找祖先组织
func (r *GroupRepo) FindAncestors(ctx context.Context, groupID int64) ([]*iamentity.Group, error) {
	// 首先获取当前组织
	group, err := r.Repo.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}

	var ancestors []*iamentity.Group
	currentGroup := *group // 解引用

	// 向上遍历找到所有祖先
	for currentGroup.ParentID != nil {
		parent, err := r.Repo.Get(ctx, *currentGroup.ParentID)
		if err != nil {
			break // 如果找不到父组织，停止查找
		}
		ancestors = append([]*iamentity.Group{parent}, ancestors...) // 插入到开头，解引用
		currentGroup = *parent                                       // 解引用
	}

	return ancestors, nil
}

// FindDescendants 查找所有后代组织
func (r *GroupRepo) FindDescendants(ctx context.Context, groupID int64) ([]*iamentity.Group, error) {
	var descendants []*iamentity.Group

	// 递归查找所有后代
	err := r.findDescendantsRecursive(ctx, groupID, &descendants)
	if err != nil {
		return nil, err
	}

	return descendants, nil
}

// findDescendantsRecursive 递归查找后代组织
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

// AddUserToGroup 将用户添加到组织
func (r *GroupRepo) AddUserToGroup(ctx context.Context, groupID, userID int64) error {
	// 检查组织是否存在
	group, err := r.Repo.Get(ctx, groupID)
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
		return errorx.Wrap(err, errorx.Database, "添加用户到组织失败")
	}

	return nil
}

// RemoveUserFromGroup 从组织中移除用户
func (r *GroupRepo) RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error {
	// 检查组织是否存在
	group, err := r.Repo.Get(ctx, groupID)
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
		return errorx.Wrap(err, errorx.Database, "从组织移除用户失败")
	}

	return nil
}

// AddDefaultRole 为组织添加默认角色
func (r *GroupRepo) AddDefaultRole(ctx context.Context, groupID, roleID int64) error {
	// 检查组织是否存在
	group, err := r.Repo.Get(ctx, groupID)
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
		return errorx.Wrap(err, errorx.Database, "添加默认角色失败")
	}

	return nil
}

// RemoveDefaultRole 移除组织的默认角色
func (r *GroupRepo) RemoveDefaultRole(ctx context.Context, groupID, roleID int64) error {
	// 检查组织是否存在
	group, err := r.Repo.Get(ctx, groupID)
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
		return errorx.Wrap(err, errorx.Database, "移除默认角色失败")
	}

	return nil
}

// GetGroupTree 获取组织树结构
func (r *GroupRepo) GetGroupTree(ctx context.Context) ([]*iamentity.Group, error) {
	// 获取所有组织
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var allGroups []*iamentity.Group
	err = model.Find(ctx, &allGroups,
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithPreload("Users"),
		orm.WithPreload("DefaultRoles"),
		orm.WithOrderBy("level", false),
		orm.WithOrderBy("name", false),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询组织树失败")
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

// CountByLevel 统计各层级组织数量
func (r *GroupRepo) CountByLevel(ctx context.Context) (map[int]int64, error) {
	type LevelCount struct {
		Level int   `json:"level"`
		Count int64 `json:"count"`
	}

	var results []LevelCount
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	err = model.Find(ctx, &results,
		orm.WithSelect("level", "COUNT(*) as count"),
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithGroupBy("level"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "统计组织层级失败")
	}

	levelMap := make(map[int]int64)
	for _, result := range results {
		levelMap[result.Level] = result.Count
	}

	return levelMap, nil
}

// SearchGroups 搜索组织（支持名称模糊搜索）
func (r *GroupRepo) SearchGroups(ctx context.Context, keyword string, limit int) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	opts := []orm.QueryOption{
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithPreload("Parent"),
		orm.WithPreload("Users"),
	}

	if keyword != "" {
		opts = append(opts, orm.WithWhere("name LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%"))
	}

	if limit > 0 {
		opts = append(opts, orm.WithLimit(limit))
	}

	err = model.Find(ctx, &groups, opts...)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "搜索组织失败")
	}

	return groups, nil
}

// FindByDefaultRoleID 根据默认角色ID查找组织
func (r *GroupRepo) FindByDefaultRoleID(ctx context.Context, roleID int64) ([]*iamentity.Group, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var groups []*iamentity.Group
	err = model.Find(ctx, &groups,
		orm.WithJoin(orm.InnerJoin("group_roles", "", orm.On("groups.id", "group_roles.group_id"))),
		orm.WithWhere("group_roles.role_id = ? AND groups.deleted_at IS NULL", roleID),
		orm.WithPreload("Parent"),
		orm.WithPreload("Users"),
		orm.WithPreload("DefaultRoles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询使用指定默认角色的组织失败")
	}

	return groups, nil
}
