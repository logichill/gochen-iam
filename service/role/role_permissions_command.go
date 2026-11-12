package role

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/errors"
)

type rolePermissionsCommand = app.Command[int64, *app.CommandRepository[*iamentity.Role, int64], iamentity.PermissionArray]

func (s *RoleService) compilePermissionsCommand() error {
	authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "permissions", Kind: auth.KindRead, Permission: "role:api:read"}}}, s.roleRepo.ExecutionDescriptor().Metadata())
	if err != nil {
		return err
	}
	s.permissionsCommand, err = app.NewCommand(app.CommandOptions[int64, *app.CommandRepository[*iamentity.Role, int64], iamentity.PermissionArray]{
		Resources: []app.CommandResource[int64]{{Name: "role", Repository: s.roleRepo.Repo, Authorizer: authorizer, Action: "permissions", ConditionPath: "CommandRepository.Get -> authorized role -> copied permission projection", Intent: func(id int64) (auth.Request, error) {
			if id <= 0 {
				return auth.Request{}, errors.NewCode(errors.InvalidInput, "role ID must be positive")
			}
			return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
		}}},
		Access: func(_ context.Context, _ int64, grants []*app.CommandGrant) (*app.CommandRepository[*iamentity.Role, int64], error) {
			return app.NewCommandRepository(s.roleRepo.Repo, grants[0])
		},
		Handler: func(ctx context.Context, id int64, roles *app.CommandRepository[*iamentity.Role, int64]) (iamentity.PermissionArray, error) {
			role, err := roles.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			if err := requireRoleOwnership(ctx, role); err != nil {
				return nil, err
			}
			return append(iamentity.PermissionArray{}, role.Permissions...), nil
		}})
	return err
}
