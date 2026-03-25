package menu

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/errorx"
)

// MenuItemRepo 菜单项仓储（全局）。
type MenuItemRepo struct {
	*db.Repo[*iamentity.MenuItem, int64]
}

// NewMenuItemRepository 创建菜单条目仓储。
func NewMenuItemRepository(o orm.IOrm) (*MenuItemRepo, error) {
	base, err := db.NewRepo[*iamentity.MenuItem, int64](o, "menu_items")
	if err != nil {
		return nil, err
	}
	return &MenuItemRepo{Repo: base}, nil
}

// Create 创建记录。
func (r *MenuItemRepo) Create(ctx context.Context, m *iamentity.MenuItem) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Create(ctx, m)
}

// Update 更新记录。
func (r *MenuItemRepo) Update(ctx context.Context, m *iamentity.MenuItem) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Save(ctx, m, orm.WithWhere("id = ? AND deleted_at IS NULL", m.GetID()))
}

// Get 返回当前值。
func (r *MenuItemRepo) Get(ctx context.Context, id int64) (*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var item iamentity.MenuItem
	if err := model.First(ctx, &item, orm.WithWhere("id = ? AND deleted_at IS NULL", id)); err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

// GetWithDeleted 按 id 查询菜单（包含软删记录）。
func (r *MenuItemRepo) GetWithDeleted(ctx context.Context, id int64) (*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var item iamentity.MenuItem
	if err := model.First(ctx, &item, orm.WithWhere("id = ?", id)); err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

// GetByCode 按编码查询。
func (r *MenuItemRepo) GetByCode(ctx context.Context, code string) (*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var item iamentity.MenuItem
	if err := model.First(ctx, &item, orm.WithWhere("code = ? AND deleted_at IS NULL", code)); err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

// GetByCodeWithDeleted 按 code 查询菜单（包含软删记录）。
func (r *MenuItemRepo) GetByCodeWithDeleted(ctx context.Context, code string) (*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var item iamentity.MenuItem
	if err := model.First(ctx, &item, orm.WithWhere("code = ?", code)); err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "菜单不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单失败")
	}
	return &item, nil
}

// ListAll 列出全部。
func (r *MenuItemRepo) ListAll(ctx context.Context) ([]*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var items []*iamentity.MenuItem
	if err := model.Find(ctx, &items, orm.WithWhere("deleted_at IS NULL")); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单列表失败")
	}
	return items, nil
}

// ListPublished 列出已发布。
func (r *MenuItemRepo) ListPublished(ctx context.Context) ([]*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var items []*iamentity.MenuItem
	if err := model.Find(ctx, &items,
		orm.WithWhere("deleted_at IS NULL AND published = ?", true),
	); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "查询菜单列表失败")
	}
	return items, nil
}

// RestoreByID 恢复软删菜单（deleted_at 置空）。
func (r *MenuItemRepo) RestoreByID(ctx context.Context, id int64) (*iamentity.MenuItem, error) {
	item, err := r.GetWithDeleted(ctx, id)
	if err != nil {
		return nil, err
	}
	if item.DeletedAt == nil {
		return item, nil
	}

	if err := item.Restore(); err != nil {
		return nil, errorx.Wrap(err, errorx.Internal, "恢复菜单失败")
	}

	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}

	// 显式置空 deleted_at，避免部分 ORM 适配器“零值/NULL 不更新”导致恢复失败。
	if err := model.UpdateValues(ctx, map[string]any{
		"deleted_at": item.DeletedAt,
		"updated_at": item.UpdatedAt,
	}, orm.WithWhere("id = ?", id)); err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "恢复菜单失败")
	}
	return item, nil
}

// PurgeByID 物理删除菜单（硬删）。
func (r *MenuItemRepo) PurgeByID(ctx context.Context, id int64) error {
	if err := r.Purge(ctx, id); err != nil {
		return errorx.Wrap(err, errorx.Database, "物理删除菜单失败")
	}
	return nil
}
