package role

import (
	"context"
	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/domain/meta"
	"gochen/errors"
)

func (access *roleCRUDAccess) capture(fn func(context.Context, *iamentity.Role) error) func(context.Context, *iamentity.Role) error {
	return func(ctx context.Context, item *iamentity.Role) error {
		snapshot, err := meta.Clone(item)
		if err != nil {
			return err
		}
		access.before[item.ID] = snapshot
		return fn(ctx, item)
	}
}

func (a *roleCRUDApplication) Execute(ctx context.Context, action string, id int64, fn func(context.Context, *iamentity.Role) error, opts ...appcrud.ExecOption) (*iamentity.Role, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function is required")
	}
	return a.execute(ctx, action, []int64{id}, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) (*iamentity.Role, error) {
		return core.Execute(ctx, action, id, access.capture(fn), opts...)
	})
}
func (a *roleCRUDApplication) ExecuteNew(ctx context.Context, action string, fn func(context.Context) (*iamentity.Role, error), opts ...appcrud.ExecOption) (*iamentity.Role, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function is required")
	}
	return a.execute(ctx, action, nil, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) (*iamentity.Role, error) {
		return core.ExecuteNew(ctx, action, fn, opts...)
	})
}
func (a *roleCRUDApplication) ExecuteBulk(ctx context.Context, action string, ids []int64, fn func(context.Context, *iamentity.Role) error, opts ...appcrud.ExecOption) ([]*iamentity.Role, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function is required")
	}
	command, err := newRoleCRUDCommand(a, action, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) ([]*iamentity.Role, error) {
		return core.ExecuteBulk(ctx, action, ids, access.capture(fn), opts...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, roleCRUDInput{IDs: ids})
}
func (a *roleCRUDApplication) ExecuteNewBulk(ctx context.Context, action string, fn func(context.Context) ([]*iamentity.Role, error), opts ...appcrud.ExecOption) ([]*iamentity.Role, error) {
	if fn == nil {
		return nil, errors.NewCode(errors.InvalidInput, "command function is required")
	}
	command, err := newRoleCRUDCommand(a, action, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], access *roleCRUDAccess) ([]*iamentity.Role, error) {
		return core.ExecuteNewBulk(ctx, action, fn, opts...)
	})
	if err != nil {
		return nil, err
	}
	return command.Execute(ctx, roleCRUDInput{})
}
