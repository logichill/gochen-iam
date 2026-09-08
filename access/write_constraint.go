package access

import "gochen/auth/scoped"

// WriteConstraint 封装 gochen 应用层写约束。
type WriteConstraint struct {
	scoped.WriteConstraint
}

type ResourceConstraint = scoped.ResourceConstraint

// NewWriteConstraint 构造带 scoped.WriteConstraint 的写入约束。
func NewWriteConstraint(constraint scoped.WriteConstraint) WriteConstraint {
	return WriteConstraint{WriteConstraint: constraint}
}

func (c WriteConstraint) Unwrap() scoped.WriteConstraint {
	return c.WriteConstraint
}
