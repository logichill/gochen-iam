package router

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	domaudited "gochen/domain/audited"
	"gochen/domain/meta"
	"gochen/errors"
)

// The HTTP model carries a request-local authorized projection. Persistence and
// Core metadata remain bound to Tenant; the response wrapper performs no I/O.
type tenantHTTPModel struct {
	iamentity.Tenant
	view svc.TenantListItem
}
type tenantHTTPApplication struct{ application *tenantCRUDApplication }

var _ appcrud.IApplication[*tenantHTTPModel, int64] = (*tenantHTTPApplication)(nil)

func (a *tenantHTTPApplication) AuditTrail(ctx context.Context, id int64, offset, limit int) ([]domaudited.AuditRecord, error) {
	return a.application.core.AuditTrail(ctx, id, offset, limit)
}

func tenantHTTPModels(out tenantCRUDResult) ([]*tenantHTTPModel, error) {
	if len(out.Items) != len(out.Views) {
		return nil, errors.NewCode(errors.Internal, "tenant projection does not match returned items")
	}
	items := make([]*tenantHTTPModel, 0, len(out.Items))
	for i, item := range out.Items {
		items = append(items, &tenantHTTPModel{Tenant: *item, view: out.Views[i]})
	}
	return items, nil
}
func (a *tenantHTTPApplication) Descriptor() auth.Descriptor { return a.application.core.Descriptor() }
func (a *tenantHTTPApplication) MaxPageSize() int            { return a.application.core.MaxPageSize() }
func (a *tenantHTTPApplication) MaxBulkSize() int            { return a.application.core.MaxBulkSize() }
func (a *tenantHTTPApplication) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	command, err := a.application.command(action, nil)
	if err != nil {
		return auth.EntryBinding{}, err
	}
	return command.AuthorizationBinding()
}
func (a *tenantHTTPApplication) Query(ctx context.Context, options query.QueryOptions) ([]*tenantHTTPModel, error) {
	options, err := meta.Clone(options)
	if err != nil {
		return nil, err
	}
	out, err := a.application.execute(ctx, appcrud.ActionList, nil, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		items, err := access.core.Query(ctx, options)
		if err != nil {
			return tenantCRUDResult{}, err
		}
		return a.application.project(ctx, access, items)
	})
	if err != nil {
		return nil, err
	}
	return tenantHTTPModels(out)
}
func (a *tenantHTTPApplication) List(ctx context.Context, offset, limit int) ([]*tenantHTTPModel, error) {
	return a.Query(ctx, query.QueryOptions{Offset: offset, Limit: limit})
}
func (a *tenantHTTPApplication) QueryCount(ctx context.Context, options query.QueryOptions) (int64, error) {
	options, err := meta.Clone(options)
	if err != nil {
		return 0, err
	}
	out, err := a.application.execute(ctx, appcrud.ActionList, nil, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		count, err := access.core.QueryCount(ctx, options)
		return tenantCRUDResult{Count: count}, err
	})
	return out.Count, err
}
func (a *tenantHTTPApplication) Count(ctx context.Context) (int64, error) {
	return a.QueryCount(ctx, query.QueryOptions{})
}
func (a *tenantHTTPApplication) Get(ctx context.Context, id int64) (*tenantHTTPModel, error) {
	out, err := a.application.execute(ctx, appcrud.ActionRead, []int64{id}, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		item, err := access.core.Get(ctx, id)
		if err != nil {
			return tenantCRUDResult{}, err
		}
		return a.application.project(ctx, access, []*iamentity.Tenant{item})
	})
	if err != nil {
		return nil, err
	}
	items, err := tenantHTTPModels(out)
	if err != nil {
		return nil, err
	}
	return items[0], nil
}
func (a *tenantHTTPApplication) Create(ctx context.Context, item *tenantHTTPModel) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "tenant is required")
	}
	_, err := a.application.execute(ctx, appcrud.ActionCreate, nil, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		return tenantCRUDResult{}, access.core.Create(ctx, &item.Tenant)
	})
	return err
}
func (a *tenantHTTPApplication) Update(ctx context.Context, item *tenantHTTPModel) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "tenant is required")
	}
	out, err := a.application.execute(ctx, appcrud.ActionUpdate, []int64{item.ID}, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		if err := access.core.Update(ctx, &item.Tenant); err != nil {
			return tenantCRUDResult{}, err
		}
		// A no-op update still has a trusted primary read snapshot.
		return a.application.project(ctx, access, []*iamentity.Tenant{&item.Tenant})
	})
	if err == nil {
		item.view = out.Views[0]
	}
	return err
}
func (a *tenantHTTPApplication) Delete(ctx context.Context, id int64) error {
	_, err := a.application.execute(ctx, appcrud.ActionDelete, []int64{id}, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		return tenantCRUDResult{}, access.core.Delete(ctx, id)
	})
	return err
}
func (a *tenantHTTPApplication) DeleteBulk(ctx context.Context, ids []int64) error {
	ids = append([]int64(nil), ids...)
	_, err := a.application.execute(ctx, appcrud.ActionDelete, ids, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		return tenantCRUDResult{}, access.core.DeleteBulk(ctx, ids)
	})
	return err
}
func (a *tenantHTTPApplication) Execute(ctx context.Context, action string, id int64, fn func(context.Context, *tenantHTTPModel) error, options ...appcrud.ExecOption) (*tenantHTTPModel, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant invocation is required")
	}
	out, err := a.application.execute(ctx, action, []int64{id}, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		item, err := access.core.Execute(ctx, action, id, func(ctx context.Context, item *iamentity.Tenant) error {
			model := &tenantHTTPModel{Tenant: *item}
			if err := fn(ctx, model); err != nil {
				return err
			}
			*item = model.Tenant
			return nil
		}, options...)
		if err != nil {
			return tenantCRUDResult{}, err
		}
		return a.application.project(ctx, access, []*iamentity.Tenant{item})
	})
	if err != nil {
		return nil, err
	}
	items, err := tenantHTTPModels(out)
	if err != nil {
		return nil, err
	}
	return items[0], nil
}
func (a *tenantHTTPApplication) ExecuteNew(ctx context.Context, action string, fn func(context.Context) (*tenantHTTPModel, error), options ...appcrud.ExecOption) (*tenantHTTPModel, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant factory is required")
	}
	out, err := a.application.execute(ctx, action, nil, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		item, err := access.core.ExecuteNew(ctx, action, func(ctx context.Context) (*iamentity.Tenant, error) {
			model, err := fn(ctx)
			if err != nil {
				return nil, err
			}
			if model == nil {
				return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
			}
			return &model.Tenant, nil
		}, options...)
		return tenantCRUDResult{Items: []*iamentity.Tenant{item}}, err
	})
	if err != nil {
		return nil, err
	}
	return &tenantHTTPModel{Tenant: *out.Items[0]}, nil
}
func (a *tenantHTTPApplication) ExecuteBulk(ctx context.Context, action string, ids []int64, fn func(context.Context, *tenantHTTPModel) error, options ...appcrud.ExecOption) ([]*tenantHTTPModel, error) {
	ids = append([]int64(nil), ids...)
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant invocation is required")
	}
	out, err := a.application.execute(ctx, action, ids, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		items, err := access.core.ExecuteBulk(ctx, action, ids, func(ctx context.Context, item *iamentity.Tenant) error {
			model := &tenantHTTPModel{Tenant: *item}
			if err := fn(ctx, model); err != nil {
				return err
			}
			*item = model.Tenant
			return nil
		}, options...)
		return tenantCRUDResult{Items: items}, err
	})
	if err != nil {
		return nil, err
	}
	models := make([]*tenantHTTPModel, 0, len(out.Items))
	for _, item := range out.Items {
		models = append(models, &tenantHTTPModel{Tenant: *item})
	}
	return models, nil
}
func (a *tenantHTTPApplication) ExecuteNewBulk(ctx context.Context, action string, fn func(context.Context) ([]*tenantHTTPModel, error), options ...appcrud.ExecOption) ([]*tenantHTTPModel, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant factory is required")
	}
	out, err := a.application.execute(ctx, action, nil, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		items, err := access.core.ExecuteNewBulk(ctx, action, func(ctx context.Context) ([]*iamentity.Tenant, error) {
			models, err := fn(ctx)
			if err != nil {
				return nil, err
			}
			items := make([]*iamentity.Tenant, 0, len(models))
			for _, model := range models {
				if model == nil {
					return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
				}
				items = append(items, &model.Tenant)
			}
			return items, nil
		}, options...)
		return tenantCRUDResult{Items: items}, err
	})
	if err != nil {
		return nil, err
	}
	models := make([]*tenantHTTPModel, 0, len(out.Items))
	for _, item := range out.Items {
		models = append(models, &tenantHTTPModel{Tenant: *item})
	}
	return models, nil
}
