package repo

import (
	"context"

	"gochen/orm"
)

type queryBuilder struct {
	ctx   context.Context
	model orm.IModel
	opts  []orm.QueryOption
}

func newQueryBuilder(model orm.IModel, ctx context.Context) *queryBuilder {
	return &queryBuilder{
		ctx:   ctx,
		model: model,
	}
}

func (q *queryBuilder) Where(expr string, args ...any) *queryBuilder {
	q.opts = append(q.opts, orm.WithWhere(expr, args...))
	return q
}

func (q *queryBuilder) Join(expr string, args ...any) *queryBuilder {
	q.opts = append(q.opts, orm.WithJoin(expr, args...))
	return q
}

func (q *queryBuilder) Preload(relations ...string) *queryBuilder {
	q.opts = append(q.opts, orm.WithPreload(relations...))
	return q
}

func (q *queryBuilder) Order(column string, desc bool) *queryBuilder {
	q.opts = append(q.opts, orm.WithOrderBy(column, desc))
	return q
}

func (q *queryBuilder) Limit(limit int) *queryBuilder {
	q.opts = append(q.opts, orm.WithLimit(limit))
	return q
}

func (q *queryBuilder) Offset(offset int) *queryBuilder {
	q.opts = append(q.opts, orm.WithOffset(offset))
	return q
}

func (q *queryBuilder) Select(columns ...string) *queryBuilder {
	q.opts = append(q.opts, orm.WithSelect(columns...))
	return q
}

func (q *queryBuilder) GroupBy(columns ...string) *queryBuilder {
	q.opts = append(q.opts, orm.WithGroupBy(columns...))
	return q
}

func (q *queryBuilder) ForUpdate() *queryBuilder {
	q.opts = append(q.opts, orm.WithForUpdate())
	return q
}

func (q *queryBuilder) First(dest any) error {
	return q.model.First(q.ctx, dest, q.opts...)
}

func (q *queryBuilder) Find(dest any) error {
	return q.model.Find(q.ctx, dest, q.opts...)
}

func (q *queryBuilder) Count() (int64, error) {
	return q.model.Count(q.ctx, q.opts...)
}

func (q *queryBuilder) Create(values ...any) error {
	return q.model.Create(q.ctx, values...)
}

func (q *queryBuilder) UpdateValues(values map[string]any) error {
	return q.model.UpdateValues(q.ctx, values, q.opts...)
}

func (q *queryBuilder) Save(entity any) error {
	return q.model.Save(q.ctx, entity, q.opts...)
}

func (q *queryBuilder) Delete() error {
	return q.model.Delete(q.ctx, q.opts...)
}
