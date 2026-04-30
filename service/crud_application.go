package service

import (
	"context"

	iamaccess "gochen-iam/access"
	appcrud "gochen/app/crud"
	appaccess "gochen/auth/access"
	"gochen/domain"
	"gochen/errors"
)

// IScopedConstraintRepository 适配 gochen-iam 仓储的显式写约束接口。
type IScopedConstraintRepository[T domain.IEntity[ID], ID comparable] interface {
	CreateWithConstraint(ctx context.Context, entity T, constraint iamaccess.WriteConstraint) error
	UpdateWithConstraint(ctx context.Context, entity T, constraint iamaccess.WriteConstraint) error
	DeleteWithConstraint(ctx context.Context, id ID, constraint iamaccess.WriteConstraint) error
}

type scopedConstraintRepositoryAdapter[T domain.IEntity[ID], ID comparable] struct {
	IScopedResourceContextRepository[T, ID]
	scopedRepo IScopedConstraintRepository[T, ID]
}

// CRUDApplication 把 gochen 原生 builder 的 WriteConstraint 适配到 gochen-iam 仓储。
type CRUDApplication[T domain.IEntity[ID], ID comparable] struct {
	*appcrud.Application[T, ID]
}

// NewCRUDApplication 创建 IAM CRUD 适配器。
func NewCRUDApplication[T domain.IEntity[ID], ID comparable](
	repo IScopedResourceContextRepository[T, ID],
	scopedRepo IScopedConstraintRepository[T, ID],
) (*CRUDApplication[T, ID], error) {
	if repo == nil {
		return nil, errors.NewCode(errors.InvalidInput, "repo cannot be nil")
	}
	if scopedRepo == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scoped repo cannot be nil")
	}
	base, err := appcrud.NewApplication[T, ID](&scopedConstraintRepositoryAdapter[T, ID]{
		IScopedResourceContextRepository: repo,
		scopedRepo:                       scopedRepo,
	}, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CRUDApplication[T, ID]{
		Application: base,
	}, nil
}

func wrapIAMConstraint(ctx context.Context, constraint appaccess.WriteConstraint) iamaccess.WriteConstraint {
	// 若 constraint 自身已经由 auth.WriteGuard 注入 metadata，优先保留；
	// 否则回落到 context 中之前 Bind 的 metadata（兼容手工绕过 authz 的路径）。
	if constraint.Metadata == (appaccess.ConstraintMetadata{}) {
		if metadata, ok := appaccess.ConstraintMetadataFromContext(ctx); ok {
			constraint.Metadata = metadata
		}
	}
	return iamaccess.NewWriteConstraint(constraint, appaccess.ConstraintMetadata{})
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) CreateWithConstraint(ctx context.Context, entity T, constraint appaccess.WriteConstraint) error {
	return r.scopedRepo.CreateWithConstraint(ctx, entity, wrapIAMConstraint(ctx, constraint))
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) UpdateWithConstraint(ctx context.Context, entity T, constraint appaccess.WriteConstraint) error {
	return r.scopedRepo.UpdateWithConstraint(ctx, entity, wrapIAMConstraint(ctx, constraint))
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) DeleteWithConstraint(ctx context.Context, id ID, constraint appaccess.WriteConstraint) error {
	return r.scopedRepo.DeleteWithConstraint(ctx, id, wrapIAMConstraint(ctx, constraint))
}

// CreateWithConstraint 在显式 guard 下创建实体。
func (a *CRUDApplication[T, ID]) CreateWithConstraint(ctx context.Context, entity T, constraint appaccess.WriteConstraint) error {
	return appcrud.NewWriteConstraintWriter[T, ID](a.Application).CreateWithConstraint(ctx, entity, constraint)
}

// UpdateWithConstraint 在显式 guard 下更新实体。
func (a *CRUDApplication[T, ID]) UpdateWithConstraint(ctx context.Context, entity T, constraint appaccess.WriteConstraint) error {
	return appcrud.NewWriteConstraintWriter[T, ID](a.Application).UpdateWithConstraint(ctx, entity, constraint)
}

// DeleteWithConstraint 在显式 guard 下删除实体。
func (a *CRUDApplication[T, ID]) DeleteWithConstraint(ctx context.Context, id ID, constraint appaccess.WriteConstraint) error {
	return appcrud.NewWriteConstraintWriter[T, ID](a.Application).DeleteWithConstraint(ctx, id, constraint)
}
