package repo

import (
	"context"
	"time"

	"gochen/errors"
)

// Add 新增
func (r *Repo[T]) Add(ctx context.Context, entity T) error {
	if err := entity.Validate(); err != nil {
		return err
	}
	if err := r.query(ctx).Create(entity); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "保存记录失败")
	}
	return nil
}

// Update 更新
func (r *Repo[T]) Update(ctx context.Context, entity T) error {
	if err := entity.Validate(); err != nil {
		return err
	}
	if err := r.query(ctx).
		Where("id = ? AND deleted_at IS NULL", entity.GetID()).
		Save(entity); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "更新记录失败")
	}
	return nil
}

// Delete 软删除
func (r *Repo[T]) Delete(ctx context.Context, id int64) error {
	now := time.Now()
	if err := r.query(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		UpdateValues(map[string]any{"deleted_at": now}); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "删除记录失败")
	}
	return nil
}

// 批量操作
func (r *Repo[T]) AddAll(ctx context.Context, entities []T) error {
	if len(entities) == 0 {
		return nil
	}
	for _, entity := range entities {
		if err := entity.Validate(); err != nil {
			return err
		}
	}
	items := make([]any, len(entities))
	for i := range entities {
		items[i] = entities[i]
	}
	if err := r.query(ctx).Create(items...); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "批量保存记录失败")
	}
	return nil
}

func (r *Repo[T]) UpdateAll(ctx context.Context, entities []T) error {
	if len(entities) == 0 {
		return nil
	}
	for _, entity := range entities {
		if err := entity.Validate(); err != nil {
			return err
		}
		if err := r.query(ctx).
			Where("id = ? AND deleted_at IS NULL", entity.GetID()).
			Save(entity); err != nil {
			return errors.WrapError(err, errors.ErrCodeDatabase, "批量更新记录失败")
		}
	}
	return nil
}

func (r *Repo[T]) DeleteAll(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now()
	if err := r.query(ctx).
		Where("id IN ? AND deleted_at IS NULL", ids).
		UpdateValues(map[string]any{"deleted_at": now}); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "批量删除记录失败")
	}
	return nil
}
