package router

import (
	"context"

	iamentity "gochen-iam/entity"
	usersvc "gochen-iam/service/user"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	domaudited "gochen/domain/audited"
)

// Standard CRUD consumes the service's fixed applications and resource plans.
type userHTTPApplication struct {
	service *usersvc.UserService
}

var _ appcrud.IApplication[*iamentity.User, int64] = (*userHTTPApplication)(nil)

func (a *userHTTPApplication) Query(ctx context.Context, options query.QueryOptions) ([]*iamentity.User, error) {
	return a.service.QueryHTTP(ctx, options)
}

func (a *userHTTPApplication) List(ctx context.Context, offset, limit int) ([]*iamentity.User, error) {
	return a.Query(ctx, query.QueryOptions{Offset: offset, Limit: limit})
}

func (a *userHTTPApplication) QueryCount(ctx context.Context, options query.QueryOptions) (int64, error) {
	return a.service.QueryCountHTTP(ctx, options)
}

func (a *userHTTPApplication) Count(ctx context.Context) (int64, error) {
	return a.QueryCount(ctx, query.QueryOptions{})
}

func (a *userHTTPApplication) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if action == appcrud.ActionList {
		return a.service.ListAuthorizationBinding()
	}
	return a.service.ExistingAuthorizationBinding(action)
}

func (a *userHTTPApplication) Descriptor() auth.Descriptor { return a.service.HTTPDescriptor() }
func (a *userHTTPApplication) MaxPageSize() int            { return a.service.HTTPMaxPageSize() }
func (a *userHTTPApplication) MaxBulkSize() int            { return a.service.HTTPMaxBulkSize() }
func (a *userHTTPApplication) AuditTrail(ctx context.Context, id int64, offset, limit int) ([]domaudited.AuditRecord, error) {
	return a.service.AuditTrailHTTP(ctx, id, offset, limit)
}
func (a *userHTTPApplication) Create(ctx context.Context, item *iamentity.User) error {
	return a.service.CreateHTTP(ctx, item)
}
func (a *userHTTPApplication) ExecuteNew(ctx context.Context, action string, fn func(context.Context) (*iamentity.User, error), options ...appcrud.ExecOption) (*iamentity.User, error) {
	return a.service.ExecuteNewHTTP(ctx, action, fn, options...)
}
func (a *userHTTPApplication) ExecuteNewBulk(ctx context.Context, action string, fn func(context.Context) ([]*iamentity.User, error), options ...appcrud.ExecOption) ([]*iamentity.User, error) {
	return a.service.ExecuteNewBulkHTTP(ctx, action, fn, options...)
}

func (a *userHTTPApplication) Get(ctx context.Context, id int64) (*iamentity.User, error) {
	return a.service.GetHTTP(ctx, id)
}

func (a *userHTTPApplication) Update(ctx context.Context, item *iamentity.User) error {
	return a.service.UpdateHTTP(ctx, item)
}

func (a *userHTTPApplication) Delete(ctx context.Context, id int64) error {
	return a.service.DeleteHTTP(ctx, id)
}

func (a *userHTTPApplication) DeleteBulk(ctx context.Context, ids []int64) error {
	return a.service.DeleteBulkHTTP(ctx, ids)
}

func (a *userHTTPApplication) Execute(ctx context.Context, action string, id int64, fn func(context.Context, *iamentity.User) error, options ...appcrud.ExecOption) (*iamentity.User, error) {
	return a.service.ExecuteHTTP(ctx, action, id, fn, options...)
}

func (a *userHTTPApplication) ExecuteBulk(ctx context.Context, action string, ids []int64, fn func(context.Context, *iamentity.User) error, options ...appcrud.ExecOption) ([]*iamentity.User, error) {
	return a.service.ExecuteBulkHTTP(ctx, action, ids, fn, options...)
}
