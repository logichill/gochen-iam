package menu

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen/runtime/errorx"
	"gochen/storage/orm"
	db "gochen/storage/orm/repo"
)

// MenuItemRepo 菜单项仓储（全局）。
type MenuItemRepo struct {
	*db.Repo[*iamentity.MenuItem, int64]
}

func NewMenuItemRepository(o orm.IOrm) (*MenuItemRepo, error) {
	base, err := db.NewRepo[*iamentity.MenuItem, int64](o, "menu_items")
	if err != nil {
		return nil, err
	}
	return &MenuItemRepo{Repo: base}, nil
}

func (r *MenuItemRepo) Create(ctx context.Context, m *iamentity.MenuItem) error {
	return r.Model().Create(ctx, m)
}

func (r *MenuItemRepo) Update(ctx context.Context, m *iamentity.MenuItem) error {
	return r.Model().Save(ctx, m, orm.WithWhere("id = ? AND deleted_at IS NULL", m.GetID()))
}

func (r *MenuItemRepo) GetByID(ctx context.Context, id int64) (*iamentity.MenuItem, error) {
	var item iamentity.MenuItem
	if err := r.Model().First(ctx, &item, orm.WithWhere("id = ? AND deleted_at IS NULL", id)); err != nil {
		if errorx.IsNotFound(err) {
			return nil, errorx.NewError(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

func (r *MenuItemRepo) GetByCode(ctx context.Context, code string) (*iamentity.MenuItem, error) {
	var item iamentity.MenuItem
	if err := r.Model().First(ctx, &item, orm.WithWhere("code = ? AND deleted_at IS NULL", code)); err != nil {
		if errorx.IsNotFound(err) {
			return nil, errorx.NewError(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

// GetByCodeWithDeleted 按 code 查询菜单（包含软删记录）。
func (r *MenuItemRepo) GetByCodeWithDeleted(ctx context.Context, code string) (*iamentity.MenuItem, error) {
	var item iamentity.MenuItem
	if err := r.Model().First(ctx, &item, orm.WithWhere("code = ?", code)); err != nil {
		if errorx.IsNotFound(err) {
			return nil, errorx.NewError(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

func (r *MenuItemRepo) ListAll(ctx context.Context) ([]*iamentity.MenuItem, error) {
	var items []*iamentity.MenuItem
	if err := r.Model().Find(ctx, &items, orm.WithWhere("deleted_at IS NULL")); err != nil {
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单列表失败")
	}
	return items, nil
}

func (r *MenuItemRepo) ListPublished(ctx context.Context) ([]*iamentity.MenuItem, error) {
	var items []*iamentity.MenuItem
	if err := r.Model().Find(ctx, &items,
		orm.WithWhere("deleted_at IS NULL AND published = ?", true),
	); err != nil {
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单列表失败")
	}
	return items, nil
}
