package repo

import (
	"context"

	sentity "gochen/domain/entity"
	"gochen/orm"
)

// Repo 基础Repository实现，依赖 gochen/orm 抽象。
// 约束：复用 shared 的实体接口，要求具备 ID 与 Validate 能力。
type Repo[T interface {
	sentity.IObject[int64]
	sentity.IValidatable
}] struct {
	orm   orm.IOrm
	model orm.IModel
}

// NewRepo 创建基础Repository实例。
func NewRepo[T interface {
	sentity.IObject[int64]
	sentity.IValidatable
}](ormEngine orm.IOrm, tableName string) *Repo[T] {
	meta := &orm.ModelMeta{
		Model: new(T),
		Table: tableName,
	}
	return &Repo[T]{
		orm:   ormEngine,
		model: ormEngine.Model(meta),
	}
}

func (r *Repo[T]) query(ctx context.Context) *queryBuilder {
	return newQueryBuilder(r.model, ctx)
}

// Model 暴露底层模型，供子类进行关联操作。
func (r *Repo[T]) Model() orm.IModel { return r.model }

// Orm 返回绑定的 ORM 引擎。
func (r *Repo[T]) Orm() orm.IOrm { return r.orm }

// Association 返回指定实体的关联操作入口。
func (r *Repo[T]) Association(owner any, name string) orm.IAssociation {
	return r.model.Association(owner, name)
}
