package service

import "gochen/errorx"

// FieldPatch 表示“对目标实体执行一次显式字段更新”。
//
// 设计意图：
// - 保留类型安全，不引入 `Name + any` 的字符串分发；
// - 只给少数需要“字段出现语义/特殊业务语义”的字段使用；
// - service 方法可接收多个 patch，但普通字段仍建议继续走 request DTO。
type FieldPatch[T any] struct {
	apply func(*T) error
}

// NewFieldPatch 构造一个字段 patch。
func NewFieldPatch[T any](apply func(*T) error) FieldPatch[T] {
	return FieldPatch[T]{apply: apply}
}

// ValueFieldPatch 基于 setter 构造一个简单值写入 patch。
func ValueFieldPatch[T any, V any](setter func(*T, V), value V) FieldPatch[T] {
	return NewFieldPatch(func(target *T) error {
		setter(target, value)
		return nil
	})
}

// Apply 执行当前 patch。
func (p FieldPatch[T]) Apply(target *T) error {
	if target == nil {
		return errorx.New(errorx.InvalidInput, "field patch target cannot be nil")
	}
	if p.apply == nil {
		return nil
	}
	return p.apply(target)
}

// ApplyFieldPatches 顺序执行一组 patch。
func ApplyFieldPatches[T any](target *T, patches ...FieldPatch[T]) error {
	for _, patch := range patches {
		if err := patch.Apply(target); err != nil {
			return err
		}
	}
	return nil
}

func sameInt64Ptr(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
