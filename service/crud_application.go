package service

import (
	"context"

	iamaccess "gochen-iam/access"
	appcrud "gochen/app/crud"
	"gochen/auth/scoped"
	"gochen/domain"
	"gochen/errors"
)

// IScopedConstraintRepository 适配 gochen-iam 仓储的显式写约束接口。
type IScopedConstraintRepository[T domain.IEntity[ID], ID comparable] interface {
	CreateWithConstraint(ctx context.Context, entity T, constraint iamaccess.WriteConstraint) error
	UpdateWithConstraint(ctx context.Context, entity T, constraint iamaccess.WriteConstraint) error
	DeleteWithConstraint(ctx context.Context, id ID, constraint iamaccess.WriteConstraint) error
}

// CRUDApplication 把 gochen 原生 builder 的 WriteConstraint 适配到 gochen-iam 仓储。
type CRUDApplication[T domain.IEntity[ID], ID comparable] struct {
	*appcrud.Application[T, ID]
	scopedRepo IScopedConstraintRepository[T, ID]
}

// NewCRUDApplication 创建 IAM CRUD 适配器。
func NewCRUDApplication[T domain.IEntity[ID], ID comparable](
	repo IScopedResourceContextRepository[T, ID],
	scopedRepo IScopedConstraintRepository[T, ID],
	options *appcrud.Options[T, ID],
) (*CRUDApplication[T, ID], error) {
	if repo == nil {
		return nil, errors.NewCode(errors.InvalidInput, "repo cannot be nil")
	}
	if scopedRepo == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scoped repo cannot be nil")
	}
	base, err := appcrud.NewApplication[T, ID](repo, options)
	if err != nil {
		return nil, err
	}
	return &CRUDApplication[T, ID]{
		Application: base,
		scopedRepo:  scopedRepo,
	}, nil
}

func wrapIAMConstraint(constraint scoped.WriteConstraint) iamaccess.WriteConstraint {
	return iamaccess.NewWriteConstraint(constraint)
}

// CreateWithConstraint 在显式 guard 下创建实体。
func (a *CRUDApplication[T, ID]) CreateWithConstraint(ctx context.Context, entity T, constraint scoped.WriteConstraint) error {
	return a.scopedRepo.CreateWithConstraint(ctx, entity, wrapIAMConstraint(constraint))
}

// UpdateWithConstraint 在显式 guard 下更新实体。
func (a *CRUDApplication[T, ID]) UpdateWithConstraint(ctx context.Context, entity T, constraint scoped.WriteConstraint) error {
	return a.scopedRepo.UpdateWithConstraint(ctx, entity, wrapIAMConstraint(constraint))
}

// DeleteWithConstraint 在显式 guard 下删除实体。
func (a *CRUDApplication[T, ID]) DeleteWithConstraint(ctx context.Context, id ID, constraint scoped.WriteConstraint) error {
	return a.scopedRepo.DeleteWithConstraint(ctx, id, wrapIAMConstraint(constraint))
}
