package repo

import (
	"context"
	ers "errors"
	"gochen/errors"
	"gochen/orm"
	"strings"
)

// Get 根据ID获取（未删除）
func (r *Repo[T]) Get(ctx context.Context, id int64) (T, error) {
	var entity T
	err := r.query(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		First(&entity)
	var zero T
	if err != nil {
		if ers.Is(err, orm.ErrNotFound) {
			return zero, errors.NewError(errors.ErrCodeNotFound, "记录不存在")
		}
		return zero, errors.WrapError(err, errors.ErrCodeDatabase, "查询记录失败")
	}
	return entity, nil
}

// Create 兼容 ICRUDRepository
func (r *Repo[T]) Create(ctx context.Context, e T) error { return r.Add(ctx, e) }

// GetByID 兼容 ICRUDRepository
func (r *Repo[T]) GetByID(ctx context.Context, id int64) (T, error) { return r.Get(ctx, id) }

// List 偏移/限制列表
func (r *Repo[T]) List(ctx context.Context, offset, limit int) ([]T, error) {
	var entities []T
	q := r.query(ctx).Where("deleted_at IS NULL")
	if offset > 0 {
		q = q.Offset(offset)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "列表查询失败")
	}
	return entities, nil
}

// Count 统计总数
func (r *Repo[T]) Count(ctx context.Context) (int64, error) {
	q := r.query(ctx).Where("deleted_at IS NULL")
	count, err := q.Count()
	if err != nil {
		return 0, errors.WrapError(err, errors.ErrCodeDatabase, "统计记录数量失败")
	}
	return count, nil
}

func (r *Repo[T]) Exists(ctx context.Context, id int64) (bool, error) {
	count, err := r.query(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		Count()
	if err != nil {
		return false, errors.WrapError(err, errors.ErrCodeDatabase, "检查记录存在性失败")
	}
	return count > 0, nil
}

func (r *Repo[T]) CountWithFilters(ctx context.Context, query *map[string]string) (int64, error) {
	qb := r.query(ctx).Where("deleted_at IS NULL")
	if query != nil {
		qb = qb.withFilters(*query)
	}
	count, err := qb.Count()
	if err != nil {
		return 0, errors.WrapError(err, errors.ErrCodeDatabase, "统计记录数量失败")
	}
	return count, nil
}

func (r *Repo[T]) Find(ctx context.Context, query *map[string]string) ([]T, error) {
	var entities []T
	qb := r.query(ctx).Where("deleted_at IS NULL")
	if query != nil {
		qb = qb.withFilters(*query)
	}
	if err := qb.Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询记录列表失败")
	}
	return entities, nil
}

func (r *Repo[T]) ListAll(ctx context.Context) ([]T, error) {
	var entities []T
	if err := r.query(ctx).Where("deleted_at IS NULL").Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询所有记录失败")
	}
	return entities, nil
}

func (r *Repo[T]) ListByIds(ctx context.Context, ids []int64) ([]T, error) {
	if len(ids) == 0 {
		return []T{}, nil
	}
	var entities []T
	if err := r.query(ctx).
		Where("id IN ? AND deleted_at IS NULL", ids).
		Find(&entities); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "根据ID列表查询记录失败")
	}
	return entities, nil
}

// withFilters 将 map 过滤条件转换为 QueryOption。
func (q *queryBuilder) withFilters(filters map[string]string) *queryBuilder {
	for key, value := range filters {
		switch {
		case strings.HasSuffix(key, "_like"):
			field := strings.TrimSuffix(key, "_like")
			q = q.Where(field+" LIKE ?", "%"+value+"%")
		case strings.HasSuffix(key, "_gt"):
			field := strings.TrimSuffix(key, "_gt")
			q = q.Where(field+" > ?", value)
		case strings.HasSuffix(key, "_gte"):
			field := strings.TrimSuffix(key, "_gte")
			q = q.Where(field+" >= ?", value)
		case strings.HasSuffix(key, "_lt"):
			field := strings.TrimSuffix(key, "_lt")
			q = q.Where(field+" < ?", value)
		case strings.HasSuffix(key, "_lte"):
			field := strings.TrimSuffix(key, "_lte")
			q = q.Where(field+" <= ?", value)
		case strings.HasSuffix(key, "_ne"):
			field := strings.TrimSuffix(key, "_ne")
			q = q.Where(field+" != ?", value)
		case strings.HasSuffix(key, "_in"):
			field := strings.TrimSuffix(key, "_in")
			parts := strings.Split(value, ",")
			q = q.Where(field+" IN ?", parts)
		case strings.HasSuffix(key, "_not_in"):
			field := strings.TrimSuffix(key, "_not_in")
			parts := strings.Split(value, ",")
			q = q.Where(field+" NOT IN ?", parts)
		default:
			q = q.Where(key+" = ?", value)
		}
	}
	return q
}
