package group

import (
	"context"

	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/errors"
)

var _ appcrud.IApplication[*iamentity.Group, int64] = (*groupWriteApplication)(nil)

func (s *GroupService) HTTPApplication() appcrud.IApplication[*iamentity.Group, int64] {
	return s.httpWriteApplication
}

func (a *groupWriteApplication) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if action == appcrud.ActionRead || action == appcrud.ActionList {
		return a.Application.AuthorizationBinding(action)
	}
	command, err := a.command(action, nil)
	if err != nil {
		return auth.EntryBinding{}, err
	}
	binding, err := command.AuthorizationBinding()
	if err != nil {
		return auth.EntryBinding{}, err
	}
	return binding, nil
}

func (a *groupWriteApplication) Create(ctx context.Context, item *iamentity.Group) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "group is required")
	}
	_, err := a.execute(ctx, appcrud.ActionCreate, nil, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		return item, core.Create(ctx, item)
	})
	return err
}

func (a *groupWriteApplication) Update(ctx context.Context, item *iamentity.Group) error {
	if item == nil {
		return errors.NewCode(errors.InvalidInput, "group is required")
	}
	result, err := a.Execute(ctx, appcrud.ActionUpdate, item.ID, func(_ context.Context, current *iamentity.Group) error {
		if current.Version != item.Version {
			return errors.NewCode(errors.Concurrency, "group version has changed")
		}
		*current = *item
		return nil
	})
	if err == nil {
		*item = *result
	}
	return err
}

func (a *groupWriteApplication) Delete(ctx context.Context, id int64) error {
	_, err := a.execute(ctx, appcrud.ActionDelete, []int64{id}, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		return nil, core.Delete(ctx, id)
	})
	return err
}

func (a *groupWriteApplication) DeleteBulk(ctx context.Context, ids []int64) error {
	_, err := a.execute(ctx, appcrud.ActionDelete, ids, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		return nil, core.DeleteBulk(ctx, ids)
	})
	return err
}

func (a *groupWriteApplication) Execute(ctx context.Context, action string, id int64, fn func(context.Context, *iamentity.Group) error, options ...appcrud.ExecOption) (*iamentity.Group, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	return a.execute(ctx, action, []int64{id}, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		return core.Execute(ctx, action, id, access.capture(fn), options...)
	})
}

func (a *groupWriteApplication) ExecuteNew(ctx context.Context, action string, fn func(context.Context) (*iamentity.Group, error), options ...appcrud.ExecOption) (*iamentity.Group, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	return a.execute(ctx, action, nil, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		return core.ExecuteNew(ctx, action, fn, options...)
	})
}

func (a *groupWriteApplication) ExecuteBulk(ctx context.Context, action string, ids []int64, fn func(context.Context, *iamentity.Group) error, options ...appcrud.ExecOption) ([]*iamentity.Group, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	command, err := newGroupWriteCommand(a, action, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) ([]*iamentity.Group, error) {
		return core.ExecuteBulk(ctx, action, ids, access.capture(fn), options...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, groupWriteInput{IDs: ids})
}

func (a *groupWriteApplication) ExecuteNewBulk(ctx context.Context, action string, fn func(context.Context) ([]*iamentity.Group, error), options ...appcrud.ExecOption) ([]*iamentity.Group, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function cannot be nil")
	}
	command, err := newGroupWriteCommand(a, action, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) ([]*iamentity.Group, error) {
		return core.ExecuteNewBulk(ctx, action, fn, options...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, groupWriteInput{})
}

func (access *groupWriteAccess) capture(fn func(context.Context, *iamentity.Group) error) func(context.Context, *iamentity.Group) error {
	return func(ctx context.Context, item *iamentity.Group) error {
		snapshot, err := meta.Clone(item)
		if err != nil {
			return err
		}
		access.before[item.ID] = snapshot
		return fn(ctx, item)
	}
}
