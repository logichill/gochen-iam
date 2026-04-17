package menu

import (
	"context"
	"strconv"
	"time"

	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	iamaccess "gochen-iam/access"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/errorx"
	"gochen/ident"
)

// MenuItemRepo 菜单项仓储（全局）。
type MenuItemRepo struct {
	*db.Repo[*iamentity.MenuItem, int64]
}

// NewMenuItemRepository 创建菜单条目仓储。
func NewMenuItemRepository(o orm.IOrm) (*MenuItemRepo, error) {
	base, err := db.NewRepo[*iamentity.MenuItem, int64](
		o,
		"menu_items",
		db.WithIDGenerator[*iamentity.MenuItem, int64](ident.DefaultInt64Generator()),
		db.WithResourceKind[*iamentity.MenuItem, int64]("iam.menu"),
		db.WithSoftDeleteColumns[*iamentity.MenuItem, int64]("deleted_at", ""),
	)
	if err != nil {
		return nil, err
	}
	return &MenuItemRepo{Repo: base}, nil
}

// Create 创建记录。
func (r *MenuItemRepo) Create(ctx context.Context, m *iamentity.MenuItem) error {
	return r.Repo.Create(ctx, m)
}

// Update 更新记录。
func (r *MenuItemRepo) Update(ctx context.Context, m *iamentity.MenuItem) error {
	return r.Repo.Update(ctx, m)
}

func (r *MenuItemRepo) CreateWithConstraint(ctx context.Context, item *iamentity.MenuItem, guard iamaccess.WriteConstraint) error {
	return r.Repo.CreateWithConstraint(assocguard.BindContext(ctx, guard), item, guard.Unwrap())
}

func (r *MenuItemRepo) UpdateWithConstraint(ctx context.Context, item *iamentity.MenuItem, guard iamaccess.WriteConstraint) error {
	return r.Repo.UpdateWithConstraint(assocguard.BindContext(ctx, guard), item, guard.Unwrap())
}

func (r *MenuItemRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
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

// FindByCode 按编码查询。
func (r *MenuItemRepo) FindByCode(ctx context.Context, code string) (*iamentity.MenuItem, error) {
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

// FindByCodeWithDeleted 按 code 查询菜单（包含软删记录）。
func (r *MenuItemRepo) FindByCodeWithDeleted(ctx context.Context, code string) (*iamentity.MenuItem, error) {
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

// RestoreByIDWithConstraint 在显式写边界下恢复软删菜单。
func (r *MenuItemRepo) RestoreByIDWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) (*iamentity.MenuItem, error) {
	item, err := r.GetWithDeleted(ctx, id)
	if err != nil {
		return nil, err
	}
	_, expectedVersion, err := r.requireConstrainedMenu(guard, id)
	if err != nil {
		return nil, err
	}
	if item.DeletedAt == nil {
		return item, nil
	}
	now := time.Now()
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	withResult, ok := model.(orm.IModelWithResult)
	if !ok {
		return nil, errorx.New(errorx.Unsupported, "guarded menu restore requires an orm model with result support")
	}
	result, err := withResult.UpdateValuesWithResult(ctx, map[string]any{
		"deleted_at": (*time.Time)(nil),
		"updated_at": now,
	}, orm.WithWhere("id = ? AND version = ?", id, expectedVersion))
	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "恢复菜单失败")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, errorx.Wrap(err, errorx.Database, "读取菜单恢复结果失败")
	}
	if affected == 0 {
		return nil, classifyMenuGuardMiss(item, expectedVersion)
	}
	item.DeletedAt = nil
	item.UpdatedAt = now
	return item, nil
}

// PurgeByID 物理删除菜单（硬删）。
func (r *MenuItemRepo) PurgeByID(ctx context.Context, id int64) error {
	if err := r.Purge(ctx, id); err != nil {
		return errorx.Wrap(err, errorx.Database, "物理删除菜单失败")
	}
	return nil
}

// PurgeByIDWithConstraint 在显式写边界下硬删菜单。
func (r *MenuItemRepo) PurgeByIDWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	item, err := r.GetWithDeleted(ctx, id)
	if err != nil {
		return err
	}
	_, expectedVersion, err := r.requireConstrainedMenu(guard, id)
	if err != nil {
		return err
	}
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	withResult, ok := model.(orm.IModelWithResult)
	if !ok {
		return errorx.New(errorx.Unsupported, "guarded menu purge requires an orm model with result support")
	}
	result, err := withResult.DeleteWithResult(ctx, orm.WithWhere("id = ? AND version = ?", id, expectedVersion))
	if err != nil {
		return errorx.Wrap(err, errorx.Database, "物理删除菜单失败")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return errorx.Wrap(err, errorx.Database, "读取菜单硬删结果失败")
	}
	if affected == 0 {
		return classifyMenuGuardMiss(item, expectedVersion)
	}
	return nil
}

func (r *MenuItemRepo) requireConstrainedMenu(guard iamaccess.WriteConstraint, id int64) (iamaccess.ResourceConstraint, uint64, error) {
	resource, err := guard.RequireResource("iam.menu", strconv.FormatInt(id, 10))
	if err != nil {
		return iamaccess.ResourceConstraint{}, 0, err
	}
	expectedVersion, err := strconv.ParseUint(resource.Revision, 10, 64)
	if err != nil {
		return iamaccess.ResourceConstraint{}, 0, errorx.Wrap(err, errorx.InvalidInput, "invalid menu write constraint revision")
	}
	return resource, expectedVersion, nil
}

func classifyMenuGuardMiss(item *iamentity.MenuItem, expectedVersion uint64) error {
	if item != nil && item.GetVersion() != expectedVersion {
		return errorx.New(errorx.Conflict, "record revision mismatch").
			WithContext("id", item.GetID()).
			WithContext("expected_version", expectedVersion).
			WithContext("actual_version", item.GetVersion())
	}
	return errorx.New(errorx.Conflict, "guarded write did not affect any record")
}
