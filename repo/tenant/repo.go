package tenant

import (
	"context"

	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	"gochen/db/orm"
	"gochen/db/orm/repo"
	"gochen/errors"
	"gochen/ident"
)

// TenantRepo 租户数据访问层
type TenantRepo struct {
	*repo.Repo[*iamentity.Tenant, int64]
}

// NewTenantRepository 创建租户仓储。
func NewTenantRepository(o orm.IOrm, idGenerator ident.IGenerator[int64]) (*TenantRepo, error) {
	base, err := repo.NewRepo[*iamentity.Tenant, int64](
		o,
		"tenants",
		repo.WithIDGenerator[*iamentity.Tenant, int64](idGenerator),
		repo.WithResourceKind[*iamentity.Tenant, int64]("iam.tenant"),
		repo.WithSoftDeleteColumns[*iamentity.Tenant, int64]("deleted_at", ""),
	)
	if err != nil {
		return nil, err
	}
	return &TenantRepo{Repo: base}, nil
}

// CreateWithConstraint 在显式写边界下创建租户。
func (r *TenantRepo) CreateWithConstraint(ctx context.Context, t *iamentity.Tenant, guard iamaccess.WriteConstraint) error {
	return r.Repo.CreateWithConstraint(assocguard.BindContext(ctx, guard), t, guard.Unwrap())
}

// UpdateWithConstraint 在显式写边界下更新租户。
func (r *TenantRepo) UpdateWithConstraint(ctx context.Context, t *iamentity.Tenant, guard iamaccess.WriteConstraint) error {
	return r.Repo.UpdateWithConstraint(assocguard.BindContext(ctx, guard), t, guard.Unwrap())
}

// DeleteWithConstraint 在显式写边界下删除租户。
func (r *TenantRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
}

// Get 根据ID获取租户（过滤软删记录）
func (r *TenantRepo) Get(ctx context.Context, id int64) (*iamentity.Tenant, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var tenant iamentity.Tenant
	err = model.First(ctx, &tenant, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "租户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询租户失败")
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
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "租户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询租户失败")
	}

	return &tenant, nil
}

func (r *TenantRepo) FindByRootScopeID(ctx context.Context, scopeID int64) (*iamentity.Tenant, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var tenant iamentity.Tenant
	err = model.First(ctx, &tenant,
		orm.WithWhere("root_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "租户不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询租户失败")
	}
	return &tenant, nil
}

func (r *TenantRepo) CountByRootScopeID(ctx context.Context, scopeID int64) (int64, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return 0, err
	}
	count, err := model.Count(ctx,
		orm.WithWhere("root_scope_id = ? AND deleted_at IS NULL", scopeID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计租户 root scope 引用失败")
	}
	return count, nil
}
