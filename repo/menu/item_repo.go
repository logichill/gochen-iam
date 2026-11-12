package menu

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	"gochen-runtime/db/orm/repo"
	"gochen/db/orm"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/gen"
)

// MenuItemRepo 菜单项仓储（全局）。
type MenuItemRepo struct {
	*repo.Repo[*iamentity.MenuItem, int64]
}

// NewMenuItemRepository 创建菜单条目仓储。
func NewMenuItemRepository(o orm.IOrm, idGenerator gen.IGenerator[int64]) (*MenuItemRepo, error) {
	base, err := repo.NewRepo[*iamentity.MenuItem, int64](
		o,
		"menu_items",
		repo.WithIDGenerator[*iamentity.MenuItem, int64](idGenerator),
		repo.WithResourceKind[*iamentity.MenuItem, int64]("iam.menu"),
		repo.WithSoftDeleteColumns[*iamentity.MenuItem, int64]("deleted_at", ""),
	)
	if err != nil {
		return nil, err
	}
	return &MenuItemRepo{Repo: base}, nil
}

// Create 创建记录。
func (r *MenuItemRepo) Create(ctx context.Context, m *iamentity.MenuItem, s spec.Spec) error {
	return r.Repo.Create(ctx, m, s)
}

// Update 更新记录。
func (r *MenuItemRepo) Update(ctx context.Context, m *iamentity.MenuItem, s spec.Spec) error {
	return r.Repo.Update(ctx, m, s)
}

// Delete 执行软删除并保留 IAM 既有语义；物理删除请使用 Purge。
func (r *MenuItemRepo) Delete(ctx context.Context, item *iamentity.MenuItem, s spec.Spec) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "menu item cannot be nil")
	}
	if item.IsDeleted() {
		return errors.NewCode(errors.Conflict, "菜单已删除").WithContext("id", item.GetID())
	}
	if err := item.SoftDelete(time.Now()); err != nil {
		return err
	}
	return r.Repo.Update(ctx, item, s)
}

// Get 返回当前值。
func (r *MenuItemRepo) Get(ctx context.Context, id int64, s spec.Spec) (*iamentity.MenuItem, error) {
	item, err := r.Repo.Get(ctx, id, s)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "菜单不存在")
		}
		return nil, err
	}
	return item, nil
}

// GetWithDeleted 按 id 查询菜单（包含软删记录）。
func (r *MenuItemRepo) GetWithDeleted(ctx context.Context, id int64, s spec.Spec) (*iamentity.MenuItem, error) {
	return r.Repo.GetWithDeleted(ctx, id, s)
}

// FindByCode 按编码查询。
func (r *MenuItemRepo) FindByCode(ctx context.Context, code string) (*iamentity.MenuItem, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var item iamentity.MenuItem
	if err := model.First(ctx, &item, orm.WithWhere("code = ? AND deleted_at IS NULL", code)); err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "菜单不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询菜单失败")
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
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "菜单不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询菜单失败")
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
		return nil, errors.Wrap(err, errors.Database, "查询菜单列表失败")
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
		return nil, errors.Wrap(err, errors.Database, "查询菜单列表失败")
	}
	return items, nil
}

// RestoreByID 恢复软删菜单（deleted_at 置空），写入前校验规约。
func (r *MenuItemRepo) RestoreByID(ctx context.Context, id int64, s spec.Spec) (*iamentity.MenuItem, error) {
	item, err := r.GetWithDeleted(ctx, id, s)
	if err != nil {
		return nil, err
	}
	if err := requireSpecMatch(s, item); err != nil {
		return nil, err
	}
	if item.DeletedAt == nil {
		return item, nil
	}
	expectedVersion := item.GetVersion()
	now := time.Now()
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	withResult, ok := model.(orm.IModelWithResult)
	if !ok {
		return nil, errors.NewCode(errors.Unsupported, "guarded menu restore requires an orm model with result support")
	}
	result, err := withResult.UpdateValuesWithResult(ctx, map[string]any{
		"deleted_at": (*time.Time)(nil),
		"updated_at": now,
	}, orm.WithWhere("id = ? AND version = ?", id, expectedVersion))
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "恢复菜单失败")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "读取菜单恢复结果失败")
	}
	if affected == 0 {
		return nil, classifyMenuGuardMiss(item, expectedVersion)
	}
	item.DeletedAt = nil
	item.UpdatedAt = now
	return item, nil
}

// PurgeByID 物理删除菜单（硬删），写入前由规约约束目标。
func (r *MenuItemRepo) PurgeByID(ctx context.Context, id int64, s spec.Spec) error {
	item, err := r.GetWithDeleted(ctx, id, s)
	if err != nil {
		return err
	}
	if err := r.Repo.Purge(ctx, item, s); err != nil {
		return errors.Wrap(err, errors.Database, "物理删除菜单失败")
	}
	return nil
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

func classifyMenuGuardMiss(item *iamentity.MenuItem, expectedVersion uint64) error {
	if item != nil && item.GetVersion() != expectedVersion {
		return errors.NewCode(errors.Conflict, "record revision mismatch").
			WithContext("id", item.GetID()).
			WithContext("expected_version", expectedVersion).
			WithContext("actual_version", item.GetVersion())
	}
	return errors.NewCode(errors.Conflict, "guarded write did not affect any record")
}
