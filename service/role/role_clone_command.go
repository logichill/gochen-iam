package role

import (
	"context"
	iamentity "gochen-iam/entity"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/errors"
)

func (a *roleCRUDApplication) cloneCommand() (*app.Command[roleCRUDInput, *roleCRUDAccess, *iamentity.Role], error) {
	return app.NewCommand(app.CommandOptions[roleCRUDInput, *roleCRUDAccess, *iamentity.Role]{Resources: a.resources["clone"], Access: func(_ context.Context, in roleCRUDInput, grants []*app.CommandGrant) (*roleCRUDAccess, error) {
		return a.bind("clone", in, grants)
	},
		Handler: func(ctx context.Context, in roleCRUDInput, access *roleCRUDAccess) (*iamentity.Role, error) {
			options := a.options
			options.Hooks = a.hooks(access)
			options.CommandGrant = access.primary
			core, err := appcrud.NewApplication(a.service.roleRepo.Repo, options)
			if err != nil {
				return nil, err
			}
			return core.ExecuteNew(ctx, "create", func(ctx context.Context) (*iamentity.Role, error) {
				source, err := access.source.Get(ctx, in.IDs[0])
				if err != nil {
					return nil, err
				}
				if err := requireRoleOwnership(ctx, source); err != nil {
					return nil, err
				}
				clone := source.Clone(in.Name)
				if clone == nil {
					return nil, errors.NewCode(errors.Internal, "clone returned nil role")
				}
				return clone, nil
			})
		}})
}
