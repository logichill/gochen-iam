package tenant

import (
	"context"
	ers "errors"

	iamentity "gochen-iam/entity"
	"gochen/data/orm"
	db "gochen/data/orm/repo"
	"gochen/errors"
)

// TenantRepo 租户数据访问层
type TenantRepo struct{ *db.Repo[*iamentity.Tenant] }

// NewTenantRepository 创建租户仓储
func NewTenantRepository(o orm.IOrm) *TenantRepo {
	return &TenantRepo{Repo: db.NewRepo[*iamentity.Tenant](o, "tenants")}
}

// Create 覆盖通用创建
func (r *TenantRepo) Create(ctx context.Context, t *iamentity.Tenant) error {
	return r.Model().Create(ctx, t)
}

// Update 覆盖通用更新
func (r *TenantRepo) Update(ctx context.Context, t *iamentity.Tenant) error {
	return r.Model().Save(ctx, t, orm.WithWhere("id = ? AND deleted_at IS NULL", t.GetID()))
}

// FindByKey 根据业务编码查找租户
func (r *TenantRepo) FindByKey(ctx context.Context, key string) (*iamentity.Tenant, error) {
	var tenant iamentity.Tenant
	err := r.Model().First(ctx, &tenant,
		orm.WithWhere("key = ? AND deleted_at IS NULL", key),
	)

	if err != nil {
		if ers.Is(err, orm.ErrNotFound) {
			return nil, errors.NewError(errors.ErrCodeNotFound, "租户不存在")
		}
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询租户失败")
	}

	return &tenant, nil
}

