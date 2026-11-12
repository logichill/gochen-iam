package role

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleGroupInput struct{ RoleID, GroupID int64 }
type roleGroupSnapshot struct {
	ID            int64
	Version       uint64
	Tenant, Owner string
	Scope         int64
}

func (s roleGroupSnapshot) condition() spec.Spec {
	return spec.And(spec.Eq(meta.ID(), s.ID), spec.Eq(meta.ByField("Version"), s.Version), spec.Eq(meta.ByDimension("tenant"), s.Tenant), spec.Eq(meta.ByDimension("owner"), s.Owner), spec.Eq(meta.ByDimension("scope"), s.Scope))
}

type roleGroupWrite struct{ Role, Group roleGroupSnapshot }
type roleGroupAccess struct {
	roles  *app.CommandRepository[*iamentity.Role, int64]
	groups *app.CommandRepository[*iamentity.Group, int64]
	write  *app.CommandWriter[roleGroupWrite, struct{}]
}
type roleGroupCommand = app.Command[roleGroupInput, *roleGroupAccess, struct{}]

func (s *RoleService) compileGroupCommands() error {
	s.groupCommands = map[string]*roleGroupCommand{}
	for _, action := range []string{"assign_group", "remove_group"} {
		resources := []app.CommandResource[roleGroupInput]{}
		for _, name := range []string{"role", "group"} {
			provider := app.IExecutionDescriptorProvider(s.roleRepo.Repo)
			resource := svc.RoleResourceKind
			kind := auth.KindRead
			if name == "group" {
				provider = s.groupRepo
				resource = svc.GroupResourceKind
				kind = auth.KindUpdate
			}
			authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: kind, Permission: "role:api:write"}}}, provider.ExecutionDescriptor().Metadata())
			if err != nil {
				return err
			}
			isRole := name == "role"
			resources = append(resources, app.CommandResource[roleGroupInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
				ConditionPath: "CommandRepository -> independently authorized role/group -> CommandWriter -> tenant and frozen versions checked in association transaction",
				Intent: func(in roleGroupInput) (auth.Request, error) {
					id := in.GroupID
					if isRole {
						id = in.RoleID
					}
					if id <= 0 {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "role and group IDs must be positive")
					}
					return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
				}})
		}
		command, err := app.NewCommand(app.CommandOptions[roleGroupInput, *roleGroupAccess, struct{}]{Resources: resources,
			Access: func(_ context.Context, in roleGroupInput, grants []*app.CommandGrant) (*roleGroupAccess, error) {
				if len(grants) != 2 || grants[0] == nil || grants[1] == nil || grants[0].Name() != "role" || grants[1].Name() != "group" {
					return nil, errors.NewCode(errors.InvalidInput, "role group command requires both grants")
				}
				a := &roleGroupAccess{}
				var err error
				a.roles, err = app.NewCommandRepository(s.roleRepo.Repo, grants[0])
				if err != nil {
					return nil, err
				}
				a.groups, err = app.NewCommandRepository(s.groupRepo, grants[1])
				if err != nil {
					return nil, err
				}
				a.write, err = app.NewCommandWriter(s.groupRepo, grants[1], func(ctx context.Context, write roleGroupWrite, condition spec.Spec) (struct{}, error) {
					if write.Role.ID != in.RoleID || write.Group.ID != in.GroupID || write.Role.Tenant != write.Group.Tenant {
						return struct{}{}, errors.NewCode(errors.Forbidden, "association differs from role intent or tenant")
					}
					err := s.groupRepo.WithinTx(ctx, func(txCtx context.Context) error {
						role, err := a.roles.Get(txCtx, in.RoleID)
						if err != nil {
							return err
						}
						group, err := a.groups.Get(txCtx, in.GroupID)
						if err != nil {
							return err
						}
						if (roleGroupSnapshot{role.ID, role.Version, role.TenantID, role.OwnerID, role.NamespaceScopeID}) != write.Role || (roleGroupSnapshot{group.ID, group.Version, group.TenantID, group.OwnerID, group.ManagedScopeID}) != write.Group {
							return errors.NewCode(errors.Concurrency, "role or group changed after authorization")
						}
						groupCondition := spec.And(condition, write.Group.condition())
						roleCondition := write.Role.condition()
						if action == "assign_group" {
							if role.Status != svc.RoleStatusActive {
								return errors.NewCode(errors.Validation, "只能分配激活状态的角色")
							}
							return s.groupRepo.AddDefaultRole(txCtx, in.GroupID, in.RoleID, groupCondition, spec.And(roleCondition, spec.Eq(meta.ByField("Status"), svc.RoleStatusActive)))
						}
						return s.groupRepo.RemoveDefaultRole(txCtx, in.GroupID, in.RoleID, groupCondition, roleCondition)
					})
					return struct{}{}, err
				})
				return a, err
			}, Handler: func(ctx context.Context, in roleGroupInput, a *roleGroupAccess) (struct{}, error) {
				role, err := a.roles.Get(ctx, in.RoleID)
				if err != nil {
					return struct{}{}, err
				}
				if err := requireRoleOwnership(ctx, role); err != nil {
					return struct{}{}, err
				}
				group, err := a.groups.Get(ctx, in.GroupID)
				if err != nil {
					return struct{}{}, err
				}
				return a.write.Write(ctx, roleGroupWrite{roleGroupSnapshot{role.ID, role.Version, role.TenantID, role.OwnerID, role.NamespaceScopeID}, roleGroupSnapshot{group.ID, group.Version, group.TenantID, group.OwnerID, group.ManagedScopeID}})
			}})
		if err != nil {
			return err
		}
		s.groupCommands[action] = command
	}
	return nil
}
