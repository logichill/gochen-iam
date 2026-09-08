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

type scopedConstraintRepositoryAdapter[T domain.IEntity[ID], ID comparable] struct {
	IScopedResourceContextRepository[T, ID]
	scopedRepo IScopedConstraintRepository[T, ID]
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
		scopedRepo:  scopedRepo,
	}, nil
}

func wrapIAMConstraint(constraint scoped.WriteConstraint) iamaccess.WriteConstraint {
	return iamaccess.NewWriteConstraint(constraint)
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) Create(ctx context.Context, entity T) error {
	return r.IScopedResourceContextRepository.Create(ctx, entity)
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) Update(ctx context.Context, entity T) error {
	return r.IScopedResourceContextRepository.Update(ctx, entity)
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) Delete(ctx context.Context, id ID) error {
	return r.IScopedResourceContextRepository.Delete(ctx, id)
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) CreateWithConstraint(ctx context.Context, entity T, constraint scoped.WriteConstraint) error {
	return r.scopedRepo.CreateWithConstraint(ctx, entity, wrapIAMConstraint(constraint))
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) UpdateWithConstraint(ctx context.Context, entity T, constraint scoped.WriteConstraint) error {
	return r.scopedRepo.UpdateWithConstraint(ctx, entity, wrapIAMConstraint(constraint))
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) DeleteWithConstraint(ctx context.Context, id ID, constraint scoped.WriteConstraint) error {
	return r.scopedRepo.DeleteWithConstraint(ctx, id, wrapIAMConstraint(constraint))
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) HasScopeDeclaration() bool {
	if p, ok := any(r.IScopedResourceContextRepository).(scoped.IScopeDeclarationProbe); ok {
		return p.HasScopeDeclaration()
	}
	return false
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) ResourceKind() string {
	if p, ok := any(r.IScopedResourceContextRepository).(scoped.IResourceKindProbe); ok {
		return p.ResourceKind()
	}
	return ""
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) ValidateWriteConstraintSupport() error {
	if p, ok := any(r.IScopedResourceContextRepository).(scoped.IConstraintWriteProbe); ok {
		return p.ValidateWriteConstraintSupport()
	}
	return nil
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) ResolveResourceByID(ctx context.Context, id ID) (scoped.Resource, error) {
	if p, ok := any(r.IScopedResourceContextRepository).(scoped.IResourceBoundaryReader[ID]); ok {
		return p.ResolveResourceByID(ctx, id)
	}
	return scoped.Resource{}, nil
}

func (r *scopedConstraintRepositoryAdapter[T, ID]) ResolveResourceByIDIncludingDeleted(ctx context.Context, id ID) (scoped.Resource, error) {
	if p, ok := any(r.IScopedResourceContextRepository).(scoped.IDeletedResourceBoundaryReader[ID]); ok {
		return p.ResolveResourceByIDIncludingDeleted(ctx, id)
	}
	return r.ResolveResourceByID(ctx, id)
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
