package access

import "gochen/app/access"

// WriteConstraint 封装 gochen 应用层写约束。
//
// Metadata 通过嵌入的 access.WriteConstraint 提供（auth.WriteGuard.WriteConstraint
// 会在生成时直接把 decision 元数据落到这里），iam 层不再额外保存一份副本，
// 避免 "context metadata" 与 "constraint metadata" 双源不同步。
type WriteConstraint struct {
	access.WriteConstraint
}

type ResourceConstraint = access.ResourceConstraint

type ResourceBoundary = access.ResourceBoundary

// NewWriteConstraint 构造带 metadata 的写入约束。metadata 会覆盖 constraint 本身携带的元数据。
func NewWriteConstraint(constraint access.WriteConstraint, metadata access.ConstraintMetadata) WriteConstraint {
	if metadata != (access.ConstraintMetadata{}) {
		constraint.Metadata = metadata
	}
	return WriteConstraint{WriteConstraint: constraint}
}

func (c WriteConstraint) Unwrap() access.WriteConstraint {
	return c.WriteConstraint
}
