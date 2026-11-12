package role

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleUserInput struct{ RoleID, UserID int64 }
type roleUserAccess struct {
	roles *app.CommandRepository[*iamentity.Role, int64]
	write *app.CommandWriter[*iamentity.Role, struct{}]
}
type roleUserCommand = app.Command[roleUserInput, *roleUserAccess, struct{}]

func (s *RoleService) compileUserCommands() error {
	s.userCommands = map[string]*roleUserCommand{}
	for _, action := range []string{"assign_user", "remove_user"} {
		resources := []app.CommandResource[roleUserInput]{}
		for _, name := range []string{"role", "user"} {
			provider, resource, kind := app.IExecutionDescriptorProvider(s.roleRepo.Repo), svc.RoleResourceKind, auth.KindRead
			if name == "user" {
				provider, resource, kind = s.userRepo, svc.UserResourceKind, auth.KindUpdate
			}
			authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: kind, Permission: "role:api:write"}}}, provider.ExecutionDescriptor().Metadata())
			if err != nil {
				return err
			}
			resources = append(resources, app.CommandResource[roleUserInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
				ConditionPath: "CommandRepository role snapshot -> independent user CommandWriter -> tenant, role dimensions/version/status and user condition in association transaction",
				Intent: func(in roleUserInput) (auth.Request, error) {
					id := in.RoleID
					if name == "user" {
						id = in.UserID
					}
					if id <= 0 {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "role and user IDs must be positive")
					}
					return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
				}})
		}
		command, err := app.NewCommand(app.CommandOptions[roleUserInput, *roleUserAccess, struct{}]{Resources: resources,
			Access: func(_ context.Context, in roleUserInput, grants []*app.CommandGrant) (*roleUserAccess, error) {
				if len(grants) != 2 || grants[0].Name() != "role" || grants[1].Name() != "user" {
					return nil, errors.NewCode(errors.InvalidInput, "role user grants are incomplete")
				}
				a := &roleUserAccess{}
				var err error
				a.roles, err = app.NewCommandRepository(s.roleRepo.Repo, grants[0])
				if err != nil {
					return nil, err
				}
				a.write, err = app.NewCommandWriter(s.userRepo, grants[1], func(ctx context.Context, role *iamentity.Role, condition spec.Spec) (struct{}, error) {
					if role == nil || role.ID != in.RoleID {
						return struct{}{}, errors.NewCode(errors.Forbidden, "role differs from association intent")
					}
					if err := requireRoleOwnership(ctx, role); err != nil {
						return struct{}{}, err
					}
					roleCondition := (roleGroupSnapshot{role.ID, role.Version, role.TenantID, role.OwnerID, role.NamespaceScopeID}).condition()
					userCondition := spec.And(condition, spec.Eq(meta.ByField("TenantID"), role.TenantID))
					err := s.userRepo.WithinTx(ctx, func(txCtx context.Context) error {
						if action == "assign_user" {
							if role.Status != svc.RoleStatusActive {
								return errors.NewCode(errors.Validation, "只能分配激活状态的角色")
							}
							grantScope := svc.ManagedScopeIDFromContext(txCtx)
							if grantScope <= 0 {
								grantScope = role.NamespaceScopeID
							}
							if err := s.userRepo.AssignRole(txCtx, in.UserID, in.RoleID, grantScope, userCondition, spec.And(roleCondition, spec.Eq(meta.ByField("Status"), svc.RoleStatusActive))); err != nil {
								return err
							}
						} else if err := s.userRepo.RemoveRole(txCtx, in.UserID, in.RoleID, userCondition, roleCondition); err != nil {
							return err
						}
						return contextx.AppendAfterCommit(txCtx, func(ctx context.Context) error {
							if action == "assign_user" {
								s.publishUserRoleAssignedEvent(ctx, in.UserID, role)
							} else {
								s.publishUserRoleRemovedEvent(ctx, in.UserID, in.RoleID)
							}
							return nil
						})
					})
					return struct{}{}, err
				})
				return a, err
			}, Handler: func(ctx context.Context, in roleUserInput, a *roleUserAccess) (struct{}, error) {
				role, err := a.roles.Get(ctx, in.RoleID)
				if err != nil {
					return struct{}{}, err
				}
				return a.write.Write(ctx, role)
			}})
		if err != nil {
			return err
		}
		s.userCommands[action] = command
	}
	return nil
}
