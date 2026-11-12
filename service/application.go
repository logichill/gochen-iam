package service

import (
	"gochen/app"
	"gochen/app/crud"
	"gochen/domain"
	"gochen/errors"
	"reflect"
)

// NewApplication 编译 IAM 强类型声明，再由应用验证并执行资源契约。
func NewApplication[T domain.IEntity[ID], ID comparable](repo crud.Repository[T, ID], access *IAMAccess, options crud.Options[T, ID]) (*crud.Application[T, ID], error) {
	if repo == nil || reflect.ValueOf(repo).Kind() == reflect.Pointer && reflect.ValueOf(repo).IsNil() {
		return nil, errors.NewCode(errors.InvalidInput, "repository is required")
	}
	if access == nil {
		return nil, errors.NewCode(errors.InvalidInput, "IAM access declarations are required")
	}
	if options.Authorizer != nil {
		return nil, errors.NewCode(errors.InvalidInput, "declared application constructs its authorizer")
	}
	provider, ok := any(repo).(app.IExecutionDescriptorProvider)
	if !ok {
		return nil, errors.NewCode(errors.InvalidInput, "repository must expose resource execution descriptor")
	}
	descriptor, err := crud.Describe(options, true)
	if err != nil {
		return nil, err
	}
	options.Authorizer, err = access.Compile(descriptor, provider.ExecutionDescriptor().Metadata())
	if err != nil {
		return nil, err
	}
	return crud.NewApplication(repo, options)
}
