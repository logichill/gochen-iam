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
	existing, err := r.GetByTenantAndMenuCode(ctx, o.TenantID, o.MenuCode)
	if err != nil && !errorx.IsNotFound(err) {
		return err
	}
	if existing == nil {
		return r.Create(ctx, o)
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

	return r.Update(ctx, existing)
}

func (r *MenuTenantOverrideRepo) DeleteByTenantAndMenuCode(ctx context.Context, tenantID, menuCode string) error {
	o, err := r.GetByTenantAndMenuCode(ctx, tenantID, menuCode)
	if err != nil {
		return err
	}
	return r.Delete(ctx, o.GetID())
}
