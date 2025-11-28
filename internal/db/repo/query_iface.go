package repo

import (
	"context"
	ers "errors"

	srepo "gochen/domain/repository"
	"gochen/errors"
	"gochen/orm"
)

// Query 执行通用查询（兼容 shared/domain/repository.IQueryableRepository）
func (r *Repo[T]) Query(ctx context.Context, opts srepo.QueryOptions) ([]T, error) {
	var entities []T
	q := r.query(ctx)
	if !opts.IncludeDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	if len(opts.Filters) > 0 {
		q = q.withFilters(toStringMap(opts.Filters))
	}
	if opts.OrderBy != "" {
		q = q.Order(opts.OrderBy, opts.OrderDesc)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}
	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if err := q.Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "通用查询失败")
	}
	return entities, nil
}

// QueryOne 查询单条记录（兼容 shared/domain/repository.IQueryableRepository）
func (r *Repo[T]) QueryOne(ctx context.Context, opts srepo.QueryOptions) (T, error) {
	var entity T
	q := r.query(ctx)
	if !opts.IncludeDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	if len(opts.Filters) > 0 {
		q = q.withFilters(toStringMap(opts.Filters))
	}
	if opts.OrderBy != "" {
		q = q.Order(opts.OrderBy, opts.OrderDesc)
	}
	err := q.First(&entity)
	var zero T
	if err != nil {
		if ers.Is(err, orm.ErrNotFound) {
			return zero, errors.NewError(errors.ErrCodeNotFound, "记录不存在")
		}
		return zero, errors.WrapError(err, errors.ErrCodeDatabase, "查询单条记录失败")
	}
	return entity, nil
}

// QueryCount 查询数量（兼容 shared/domain/repository.IQueryableRepository）
func (r *Repo[T]) QueryCount(ctx context.Context, opts srepo.QueryOptions) (int64, error) {
	q := r.query(ctx)
	if !opts.IncludeDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	if len(opts.Filters) > 0 {
		q = q.withFilters(toStringMap(opts.Filters))
	}
	count, err := q.Count()
	if err != nil {
		return 0, errors.WrapError(err, errors.ErrCodeDatabase, "统计数量失败")
	}
	return count, nil
}
