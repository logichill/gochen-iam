package group

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type groupDeleteValidationAccess struct {
	group    *app.CommandRepository[*iamentity.Group, int64]
	children *app.CommandReader[struct{}, int64]
	members  *app.CommandReader[struct{}, int64]
}
type groupDeleteCommand = app.Command[int64, groupDeleteValidationAccess, struct{}]

func (s *GroupService) compileDeleteCommands() error {
	s.deleteCommands = map[string]*groupDeleteCommand{}
	for _, action := range []string{"validate_delete"} {
		command, err := s.compileDeleteCommand(action)
		if err != nil {
			return err
		}
		s.deleteCommands[action] = command
	}
	return nil
}

func (s *GroupService) compileDeleteCommand(action string) (*groupDeleteCommand, error) {
	resources := make([]app.CommandResource[int64], 0, 3)
	for _, resource := range []struct {
		name, kind string
		provider   app.IExecutionDescriptorProvider
	}{
		{"group", svc.GroupResourceKind, s.groupRepo},
		{"children", svc.GroupResourceKind, s.groupRepo.Repo},
		{"members", svc.UserResourceKind, s.userRepo.Repo},
	} {
		primary := resource.name == "group"
		kind := auth.KindRead
		if action == "delete" && primary {
			kind = auth.KindDelete
		}
		descriptor := auth.Descriptor{Resource: resource.kind, Actions: []auth.Action{{
			Name: action + "_" + resource.name, Kind: kind, Permission: svc.GroupPermissionSet.Code(iamperm.ActionDelete),
		}}}
		var authorizer *auth.Authorizer
		var err error
		if primary {
			authorizer, err = s.authorizer.Compile(descriptor, resource.provider.ExecutionDescriptor().Metadata())
		} else {
			// Only existence is disclosed for the trusted group. All same-tenant
			// associations must block deletion, including targets outside its scope.
			descriptor.Resource = "iam.group." + resource.name + "_exists"
			authorizer, err = auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData,
				Rules: []auth.Rule{{ID: descriptor.Resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true}}},
				auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: resource.provider.ExecutionDescriptor().Metadata()})
		}
		if err != nil {
			return nil, err
		}
		resources = append(resources, app.CommandResource[int64]{Name: resource.name, Repository: resource.provider,
			Authorizer: authorizer, Action: action + "_" + resource.name,
			ConditionPath: "CommandRepository.Get -> authorized group -> independently conditioned child/member count without relation hydration",
			Intent: func(id int64) (auth.Request, error) {
				if id <= 0 {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "group ID must be positive")
				}
				if primary {
					return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
				}
				return auth.Request{}, nil
			}})
	}
	return app.NewCommand(app.CommandOptions[int64, groupDeleteValidationAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (groupDeleteValidationAccess, error) {
			var access groupDeleteValidationAccess
			var err error
			if len(grants) != 3 || grants[0] == nil || grants[1] == nil || grants[2] == nil || grants[0].Name() != "group" || grants[1].Name() != "children" || grants[2].Name() != "members" {
				return access, errors.NewCode(errors.InvalidInput, "group deletion validation requires all resource grants")
			}
			access.group, err = app.NewCommandRepository(s.groupRepo, grants[0])
			if err != nil {
				return access, err
			}
			access.children, err = app.NewCommandReader(s.groupRepo.Repo, grants[1], func(ctx context.Context, _ struct{}, condition spec.Spec) (int64, error) {
				return s.groupRepo.Repo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("ParentID"), id)))
			})
			if err != nil {
				return access, err
			}
			access.members, err = app.NewCommandReader(s.userRepo.Repo, grants[2], func(ctx context.Context, _ struct{}, condition spec.Spec) (int64, error) {
				counts, err := s.userRepo.GroupMemberCounts(ctx, []int64{id}, condition)
				return counts[id], err
			})
			return access, err
		}, Handler: func(ctx context.Context, id int64, access groupDeleteValidationAccess) (struct{}, error) {
			validate := func(ctx context.Context) error {
				group, err := access.group.Get(ctx, id)
				if err != nil {
					return err
				}
				children, err := access.children.Read(ctx, struct{}{})
				if err != nil {
					return err
				}
				if children > 0 {
					return errors.NewCode(errors.Validation, "不能删除有子组织的组织，请先处理子组织")
				}
				members, err := access.members.Read(ctx, struct{}{})
				if err != nil {
					return err
				}
				if members > 0 {
					return errors.NewCode(errors.Validation, "不能删除有用户的组织，请先移除用户")
				}
				if action == "delete" {
					return access.group.Delete(ctx, group)
				}
				return nil
			}
			if action == "delete" {
				return struct{}{}, s.groupRepo.WithinTx(ctx, validate)
			}
			return struct{}{}, validate(ctx)
		}})
}
