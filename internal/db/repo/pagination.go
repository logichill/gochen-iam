package repo

import (
	"context"
	"math"

	idb "gochen-iam/internal/db"
	"gochen/errors"
)

func (r *Repo[T]) ListPage(ctx context.Context, options *idb.QueryOptions) (*idb.PagedResult[T], error) {
	var entities []T
	var total int64

	q := r.query(ctx).Where("deleted_at IS NULL")
	if options.Filters != nil {
		q = q.withFilters(options.Filters)
	}
	if options.Advanced != nil {
		q = r.applyAdvancedFilters(q, options.Advanced)
	}

	total, err := q.Count()
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "统计总记录数失败")
	}

	q = r.applySorting(q, options)
	if len(options.Fields) > 0 {
		q = q.Select(options.Fields...)
	}
	offset := (options.Page - 1) * options.Size
	q = q.Offset(offset).Limit(options.Size)

	if err := q.Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "分页查询失败")
	}

	totalPages := int(math.Ceil(float64(total) / float64(options.Size)))
	result := make([]*T, len(entities))
	for i := range entities {
		result[i] = &entities[i]
	}

	return &idb.PagedResult[T]{
		Data:       result,
		Total:      total,
		Page:       options.Page,
		Size:       options.Size,
		TotalPages: totalPages,
	}, nil
}
