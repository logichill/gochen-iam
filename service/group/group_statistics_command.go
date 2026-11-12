package group

import (
	"context"

	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type groupStatisticsGroups struct {
	Total   int64
	ByLevel map[int]int64
}
type groupStatisticsUsers struct {
	Total    int64
	ByStatus map[string]int64
}
type groupStatisticsAccess struct {
	groups *app.CommandReader[struct{}, groupStatisticsGroups]
	users  *app.CommandReader[struct{}, groupStatisticsUsers]
	roles  *app.CommandReader[struct{}, int64]
}
type groupStatisticsCommand = app.Command[struct{}, groupStatisticsAccess, *svc.StatisticsResponse]

func (s *GroupService) compileStatisticsCommands() error {
	s.statisticsCommands = map[string]*groupStatisticsCommand{}
	for _, action := range []string{"statistics", "http_statistics"} {
		var policies []auth.IPolicy
		if action == "http_statistics" {
			policies = []auth.IPolicy{groupAssociationEntryPolicy{}}
		}
		resources := make([]app.CommandResource[struct{}], 0, 3)
		for _, resource := range []struct {
			name, kind string
			provider   app.IExecutionDescriptorProvider
			path       string
		}{
			{"groups", svc.GroupResourceKind, s.groupRepo, "CommandReader -> group QueryCount/CountByLevel with group spec before count and pagination"},
			{"users", svc.UserResourceKind, s.userRepo, "CommandReader -> base user QueryCount/CountByStatus with user spec before count and pagination, without relation hydration"},
			{"roles", svc.RoleResourceKind, s.roleRepo.Repo, "CommandReader -> base role QueryCount with role spec, without namespace hydration"},
		} {
			descriptor := auth.Descriptor{Resource: resource.kind, Actions: []auth.Action{{Name: action, Kind: auth.KindList, Permission: svc.GroupPermissionSet.Code(iamperm.ActionRead)}}}
			authorizer, err := s.authorizer.Compile(descriptor, resource.provider.ExecutionDescriptor().Metadata(), policies...)
			if err != nil {
				return err
			}
			resources = append(resources, app.CommandResource[struct{}]{Name: resource.name, Repository: resource.provider, Authorizer: authorizer, Action: action, ConditionPath: resource.path,
				Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil },
			})
		}
		command, err := app.NewCommand(app.CommandOptions[struct{}, groupStatisticsAccess, *svc.StatisticsResponse]{Resources: resources,
			Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (groupStatisticsAccess, error) {
				return s.bindStatisticsAccess(action, grants)
			}, Handler: func(ctx context.Context, _ struct{}, access groupStatisticsAccess) (*svc.StatisticsResponse, error) {
				groups, err := access.groups.Read(ctx, struct{}{})
				if err != nil {
					return nil, err
				}
				users, err := access.users.Read(ctx, struct{}{})
				if err != nil {
					return nil, err
				}
				roles, err := access.roles.Read(ctx, struct{}{})
				if err != nil {
					return nil, err
				}
				return &svc.StatisticsResponse{TotalGroups: groups.Total, GroupsByLevel: groups.ByLevel, TotalUsers: users.Total,
					ActiveUsers: users.ByStatus[svc.UserStatusActive], UsersByStatus: users.ByStatus, TotalRoles: roles}, nil
			}})
		if err != nil {
			return err
		}
		s.statisticsCommands[action] = command
	}
	return nil
}

func (s *GroupService) bindStatisticsAccess(action string, grants []*app.CommandGrant) (groupStatisticsAccess, error) {
	var access groupStatisticsAccess
	if len(grants) != 3 {
		return access, errors.NewCode(errors.InvalidInput, "group statistics requires all three resource grants")
	}
	for i, resource := range []struct{ name, kind string }{{"groups", svc.GroupResourceKind}, {"users", svc.UserResourceKind}, {"roles", svc.RoleResourceKind}} {
		if grants[i] == nil || grants[i].Name() != resource.name {
			return access, errors.NewCode(errors.InvalidInput, "group statistics grant differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return access, err
		}
		if req.Resource != resource.kind || req.Action != action {
			return access, errors.NewCode(errors.InvalidInput, "group statistics action differs from its declaration")
		}
	}
	var err error
	access.groups, err = app.NewCommandReader(s.groupRepo, grants[0], func(ctx context.Context, _ struct{}, condition spec.Spec) (groupStatisticsGroups, error) {
		total, err := s.groupRepo.QueryCount(ctx, query.QueryOptions{}, condition)
		if err != nil {
			return groupStatisticsGroups{}, err
		}
		levels, err := s.groupRepo.CountByLevel(ctx, condition)
		return groupStatisticsGroups{Total: total, ByLevel: levels}, err
	})
	if err != nil {
		return access, err
	}
	access.users, err = app.NewCommandReader(s.userRepo, grants[1], func(ctx context.Context, _ struct{}, condition spec.Spec) (groupStatisticsUsers, error) {
		total, err := s.userRepo.Repo.QueryCount(ctx, query.QueryOptions{}, condition)
		if err != nil {
			return groupStatisticsUsers{}, err
		}
		statuses, err := s.userRepo.CountByStatus(ctx, condition)
		return groupStatisticsUsers{Total: total, ByStatus: statuses}, err
	})
	if err != nil {
		return access, err
	}
	access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[2], func(ctx context.Context, _ struct{}, condition spec.Spec) (int64, error) {
		return s.roleRepo.Repo.QueryCount(ctx, query.QueryOptions{}, condition)
	})
	return access, err
}

func (s *GroupService) GroupStatisticsHTTP(ctx context.Context) (*svc.StatisticsResponse, error) {
	return s.statisticsCommands["http_statistics"].Execute(ctx, struct{}{})
}

func (s *GroupService) StatisticsAuthorizationBinding() (auth.EntryBinding, error) {
	return s.statisticsCommands["http_statistics"].AuthorizationBinding()
}
