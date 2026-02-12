package tenant

import (
	"context"

	iamentity "gochen-iam/entity"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/errorx"
	"gochen/ident/generator"
)

// TenantRepo 租户数据访问层
type TenantRepo struct {
	*db.Repo[*iamentity.Tenant, int64]
}

// NewTenantRepository 创建租户仓储
func NewTenantRepository(o orm.IOrm) (*TenantRepo, error) {
	base, err := db.NewRepo[*iamentity.Tenant, int64](
		o,
		"tenants",
		db.WithIDGenerator[*iamentity.Tenant, int64](generator.DefaultInt64Generator()),
	)
	if err != nil {
		return nil, err
	}
	return &TenantRepo{Repo: base}, nil
}

// Create 覆盖通用创建
func (r *TenantRepo) Create(ctx context.Context, t *iamentity.Tenant) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Create(ctx, t)
}

// Update 覆盖通用更新
func (r *TenantRepo) Update(ctx context.Context, t *iamentity.Tenant) error {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	return model.Save(ctx, t, orm.WithWhere("id = ? AND deleted_at IS NULL", t.GetID()))
}

// GetByID 根据ID获取租户（过滤软删记录）
func (r *TenantRepo) GetByID(ctx context.Context, id int64) (*iamentity.Tenant, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var tenant iamentity.Tenant
	err = model.First(ctx, &tenant, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "租户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询租户失败")
	}
	return &tenant, nil
}

// FindByKey 根据业务编码查找租户
func (r *TenantRepo) FindByKey(ctx context.Context, key string) (*iamentity.Tenant, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var tenant iamentity.Tenant
	err = model.First(ctx, &tenant,
		orm.WithWhere("key = ? AND deleted_at IS NULL", key),
	)

	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "租户不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询租户失败")
	}

	return &tenant, nil
}
