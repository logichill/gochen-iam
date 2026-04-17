package access

import "gochen/app/access"

// WriteConstraint 封装 gochen 应用层写约束，并携带当前决策元数据。
type WriteConstraint struct {
	access.WriteConstraint
	Metadata access.ConstraintMetadata
}

type ResourceConstraint = access.ResourceConstraint

type ResourceBoundary = access.ResourceBoundary

func NewWriteConstraint(constraint access.WriteConstraint, metadata access.ConstraintMetadata) WriteConstraint {
	return WriteConstraint{
		WriteConstraint: constraint,
		Metadata:        metadata,
	}
}

func (c WriteConstraint) Unwrap() access.WriteConstraint {
	return c.WriteConstraint
}
