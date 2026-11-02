package router

import (
	iamentity "gochen-iam/entity"
	"gochen/app"
	"gochen/domain/meta"
)

func routeExecution[T any]() app.ExecutionDescriptor {
	metadata, err := meta.Describe[T]()
	if err != nil {
		panic(err)
	}
	descriptor, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		panic(err)
	}
	return descriptor
}

func (menuRouteTestRepo) ExecutionDescriptor() app.ExecutionDescriptor {
	return routeExecution[*iamentity.MenuItem]()
}
func (routeScopedRepo[T]) ExecutionDescriptor() app.ExecutionDescriptor { return routeExecution[T]() }
