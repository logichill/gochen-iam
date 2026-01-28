package menu

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	"gochen/runtime/errorx"
	"gochen/storage/orm"
	db "gochen/storage/orm/repo"
)

// MenuTenantOverrideRepo 菜单租户覆盖仓储。
type MenuTenantOverrideRepo struct {
	*db.Repo[*iamentity.MenuTenantOverride, int64]
}

func NewMenuTenantOverrideRepository(o orm.IOrm) (*MenuTenantOverrideRepo, error) {
	base, err := db.NewRepo[*iamentity.MenuTenantOverride, int64](o, "menu_tenant_overrides")
	if err != nil {
		return nil, err
	}
	return &MenuTenantOverrideRepo{Repo: base}, nil
}

func (r *MenuTenantOverrideRepo) Create(ctx context.Context, o *iamentity.MenuTenantOverride) error {
	return r.Model().Create(ctx, o)
}

func (r *MenuTenantOverrideRepo) Update(ctx context.Context, o *iamentity.MenuTenantOverride) error {
	return r.Model().Save(ctx, o, orm.WithWhere("id = ? AND deleted_at IS NULL", o.GetID()))
}

func (r *MenuTenantOverrideRepo) GetByTenantAndMenuCode(ctx context.Context, tenantID, menuCode string) (*iamentity.MenuTenantOverride, error) {
	var o iamentity.MenuTenantOverride
	if err := r.Model().First(ctx, &o,
		orm.WithWhere("tenant_id = ? AND menu_code = ? AND deleted_at IS NULL", tenantID, menuCode),
	); err != nil {
		if errorx.IsNotFound(err) {
			return nil, errorx.NewError(errorx.NotFound, "菜单覆盖不存在")
		}
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单覆盖失败")
	}
	return &o, nil
}

func (r *MenuTenantOverrideRepo) ListByTenant(ctx context.Context, tenantID string) ([]*iamentity.MenuTenantOverride, error) {
	var overrides []*iamentity.MenuTenantOverride
	if err := r.Model().Find(ctx, &overrides,
		orm.WithWhere("tenant_id = ? AND deleted_at IS NULL", tenantID),
	); err != nil {
		return nil, errorx.WrapError(err, errorx.Database, "查询菜单覆盖列表失败")
	}
	return overrides, nil
}

// UpsertByTenantAndMenuCode 以 (tenant_id, menu_code) 为 key 执行 upsert。
func (r *MenuTenantOverrideRepo) UpsertByTenantAndMenuCode(ctx context.Context, o *iamentity.MenuTenantOverride) error {
	// 注意：menu_tenant_overrides 存在 (tenant_id, menu_code) 唯一索引，
	// 若底层删除为软删且索引不含 deleted_at，则“删了也不能重建”。
	// 这里 upsert 需要能识别软删记录并恢复后更新。
	var existing iamentity.MenuTenantOverride
	err := r.Model().First(ctx, &existing,
		orm.WithWhere("tenant_id = ? AND menu_code = ?", o.TenantID, o.MenuCode),
	)
	if err != nil {
		if errorx.IsNotFound(err) {
			return r.Create(ctx, o)
		}
		return errorx.WrapError(err, errorx.Database, "查询菜单覆盖失败")
	}

	// 如已软删则恢复（避免唯一索引阻塞重建）
	if existing.DeletedAt != nil {
		existing.Restore()
	}

	// 覆盖可变字段
	existing.Title = o.Title
	existing.Path = o.Path
	existing.Icon = o.Icon
	existing.Route = o.Route
	existing.Component = o.Component
	existing.Order = o.Order
	existing.Hidden = o.Hidden
	existing.Disabled = o.Disabled
	existing.SetUpdatedAt(time.Now())

	// 不能用 Update（其 where 含 deleted_at IS NULL）；直接按 id 保存即可。
	return r.Model().Save(ctx, &existing, orm.WithWhere("id = ?", existing.GetID()))
}

func (r *MenuTenantOverrideRepo) DeleteByTenantAndMenuCode(ctx context.Context, tenantID, menuCode string) error {
	o, err := r.GetByTenantAndMenuCode(ctx, tenantID, menuCode)
	if err != nil {
		return err
	}
	return r.Delete(ctx, o.GetID())
}
