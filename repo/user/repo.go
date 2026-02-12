package user

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/domain/crud"
	"gochen/errorx"
)

// UserRepo 用户数据访问层
type UserRepo struct {
	*db.Repo[*iamentity.User, int64]
}

// NewUserRepository 创建用户Repository
func NewUserRepository(o orm.IOrm) (*UserRepo, error) {
	base, err := db.NewRepo[*iamentity.User, int64](o, "users")
	if err != nil {
		return nil, err
	}
	return &UserRepo{Repo: base}, nil
}

// shared 原生 ICRUDRepository 方法由 CrudBase 提供

// Create 覆盖通用创建，省略非表字段（version/created_by/updated_by/deleted_by）
func (r *UserRepo) Create(ctx context.Context, u *iamentity.User) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Create(ctx, u)
}

// Update 覆盖通用更新，省略非表字段
func (r *UserRepo) Update(ctx context.Context, u *iamentity.User) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Save(ctx, u, orm.WithWhere("id = ? AND deleted_at IS NULL", u.GetID()))
}

// GetByID 根据ID获取用户（过滤软删记录）
func (r *UserRepo) GetByID(ctx context.Context, id int64) (*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var user iamentity.User
	err = model.First(ctx, &user, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "用户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}
	return &user, nil
}

// GetWithRelations 根据ID获取用户及关联数据
func (r *UserRepo) GetWithRelations(ctx context.Context, id int64) (*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var user iamentity.User
	err = model.First(ctx, &user,
		orm.WithWhere("users.id = ? AND users.deleted_at IS NULL", id),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "用户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}

	return &user, nil
}

// FindByEmail 根据邮箱查找用户
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var user iamentity.User
	err = model.First(ctx, &user,
		orm.WithWhere("email = ? AND deleted_at IS NULL", email),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "用户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}

	return &user, nil
}

// FindByUsername 根据用户名查找用户
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var user iamentity.User
	err = model.First(ctx, &user,
		orm.WithWhere("username = ? AND deleted_at IS NULL", username),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "用户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}

	return &user, nil
}

// UpdateLastLogin 更新最后登录时间
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID int64) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.UpdateValues(ctx, map[string]any{
		"last_login_at": time.Now(),
	}, orm.WithWhere("id = ? AND deleted_at IS NULL", userID))

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "更新最后登录时间失败")
	}

	return nil
}

// FindByStatus 根据状态查找用户
func (r *UserRepo) FindByStatus(ctx context.Context, status string) ([]*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var users []*iamentity.User
	err = model.Find(ctx, &users,
		orm.WithWhere("status = ? AND deleted_at IS NULL", status),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询用户失败")
	}

	return users, nil
}

// FindByGroupID 根据组织ID查找用户
func (r *UserRepo) FindByGroupID(ctx context.Context, groupID int64) ([]*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var users []*iamentity.User
	err = model.Find(ctx, &users,
		orm.WithJoin(orm.InnerJoin("user_groups", "", orm.On("users.id", "user_groups.user_id"))),
		orm.WithWhere("user_groups.group_id = ? AND users.deleted_at IS NULL", groupID),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询组织用户失败")
	}

	return users, nil
}

// FindByRoleID 根据角色ID查找用户
func (r *UserRepo) FindByRoleID(ctx context.Context, roleID int64) ([]*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var users []*iamentity.User
	err = model.Find(ctx, &users,
		orm.WithJoin(orm.InnerJoin("user_roles", "", orm.On("users.id", "user_roles.user_id"))),
		orm.WithWhere("user_roles.role_id = ? AND users.deleted_at IS NULL", roleID),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询角色用户失败")
	}

	return users, nil
}

// AssignToGroup 将用户分配到组织
func (r *UserRepo) AssignToGroup(ctx context.Context, userID, groupID int64) error {
	// 检查用户是否存在
	user, err := r.Repo.Get(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Groups").
		Append(ctx, &iamentity.Group{Entity: crud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "分配用户到组织失败")
	}

	return nil
}

// RemoveFromGroup 从组织中移除用户
func (r *UserRepo) RemoveFromGroup(ctx context.Context, userID, groupID int64) error {
	// 检查用户是否存在
	user, err := r.Repo.Get(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Groups").
		Delete(ctx, &iamentity.Group{Entity: crud.Entity[int64]{ID: groupID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "从组织移除用户失败")
	}

	return nil
}

// AssignRole 为用户分配角色
func (r *UserRepo) AssignRole(ctx context.Context, userID, roleID int64) error {
	// 检查用户是否存在
	user, err := r.Repo.Get(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Roles").
		Append(ctx, &iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "分配角色失败")
	}

	return nil
}

// RemoveRole 移除用户角色
func (r *UserRepo) RemoveRole(ctx context.Context, userID, roleID int64) error {
	// 检查用户是否存在
	user, err := r.Repo.Get(ctx, userID)
	if err != nil {
		return err
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	err = model.Association(user, "Roles").
		Delete(ctx, &iamentity.Role{Entity: crud.Entity[int64]{ID: roleID}})

	if err != nil {
		return errorx.Wrap(err, errorx.Database, "移除角色失败")
	}

	return nil
}

// CountByStatus 统计各状态用户数量
func (r *UserRepo) CountByStatus(ctx context.Context) (map[string]int64, error) {
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
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithGroupBy("status"),
	)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "统计用户状态失败")
	}

	statusMap := make(map[string]int64)
	for _, result := range results {
		statusMap[result.Status] = result.Count
	}

	return statusMap, nil
}

// SearchUsers 搜索用户（支持用户名、邮箱模糊搜索）
func (r *UserRepo) SearchUsers(ctx context.Context, keyword string, limit int) ([]*iamentity.User, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var users []*iamentity.User
	opts := []orm.QueryOption{
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithPreload("Groups"),
		orm.WithPreload("Roles"),
	}

	if keyword != "" {
		opts = append(opts, orm.WithWhere("username LIKE ? OR email LIKE ?", "%"+keyword+"%", "%"+keyword+"%"))
	}

	if limit > 0 {
		opts = append(opts, orm.WithLimit(limit))
	}

	err = model.Find(ctx, &users, opts...)

	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "搜索用户失败")
	}

	return users, nil
}
