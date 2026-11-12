package user

import (
	"context"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type userHTTPListAccess struct {
	users  *appcrud.Application[*iamentity.User, int64]
	groups *app.CommandReader[[]int64, relations.Catalog[*iamentity.Group]]
	roles  *app.CommandReader[[]int64, relations.Catalog[*iamentity.Role]]
}
type userHTTPListCommand = app.Command[query.QueryOptions, *userHTTPListAccess, []*iamentity.User]

type userHTTPListQuery struct {
	Options   query.QueryOptions
	Condition spec.Spec
}

// Core retains pagination and query normalization; this private repository
// passes its final query through the same invocation's managed capability.
type userHTTPListRepository struct {
	*ormrepo.Repo[*iamentity.User, int64]
	users *app.CommandReader[userHTTPListQuery, []*iamentity.User]
}

func (r *userHTTPListRepository) Query(ctx context.Context, options query.QueryOptions, condition spec.Spec) ([]*iamentity.User, error) {
	return r.users.Read(ctx, userHTTPListQuery{Options: options, Condition: condition})
}

func (s *UserService) compileHTTPList() error {
	options := appcrud.Options[*iamentity.User, int64]{Resource: "user", ActionPermissions: map[string]string{
		appcrud.ActionRead: svc.UserPermissionSet.Code(iamperm.ActionRead),
		appcrud.ActionList: svc.UserPermissionSet.Code(iamperm.ActionRead),
	}}
	descriptor, err := appcrud.Describe(options, false)
	if err != nil {
		return err
	}
	primary, err := s.authorizer.Compile(descriptor, s.userRepo.Repo.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{})
	if err != nil {
		return err
	}
	options.Authorizer = primary
	s.httpListCounts, err = appcrud.NewReadApplication[*iamentity.User, int64](s.userRepo.Repo, options)
	if err != nil {
		return err
	}
	resources := []app.CommandResource[query.QueryOptions]{{Name: "users", Repository: s.userRepo.Repo,
		Authorizer: primary, Action: appcrud.ActionList,
		Intent:        func(query.QueryOptions) (auth.Request, error) { return auth.Request{}, nil },
		ConditionPath: "Core normalized query -> CommandReader -> actual user repository with intersected SQL conditions before pagination; returned user IDs authorize association sources",
	}}
	for _, name := range []string{"groups", "roles"} {
		provider, resource := s.directoryProvider(name)
		authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: resource,
			Actions: []auth.Action{{Name: "http_list_" + name, Kind: auth.KindList, Permission: svc.UserPermissionSet.Code(iamperm.ActionRead)}}},
			provider.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{})
		if err != nil {
			return err
		}
		resources = append(resources, app.CommandResource[query.QueryOptions]{Name: name, Repository: provider, Authorizer: authorizer,
			Action: "http_list_" + name, Intent: func(query.QueryOptions) (auth.Request, error) { return auth.Request{}, nil },
			ConditionPath: "trusted returned user IDs -> CommandReader -> independent target SQL condition before association JOIN and complete role/group projection",
		})
	}
	s.httpListCommand, err = app.NewCommand(app.CommandOptions[query.QueryOptions, *userHTTPListAccess, []*iamentity.User]{Resources: resources,
		Access: func(_ context.Context, _ query.QueryOptions, grants []*app.CommandGrant) (*userHTTPListAccess, error) {
			return s.bindHTTPList(options, grants)
		},
		Handler: func(ctx context.Context, options query.QueryOptions, access *userHTTPListAccess) ([]*iamentity.User, error) {
			users, err := access.users.Query(ctx, options)
			if err != nil {
				return nil, err
			}
			ids := make([]int64, 0, len(users))
			byID := make(map[int64]*iamentity.User, len(users))
			for _, user := range users {
				ids = append(ids, user.ID)
				byID[user.ID] = user
			}
			groups, err := access.groups.Read(ctx, ids)
			if err != nil {
				return nil, err
			}
			roles, err := access.roles.Read(ctx, ids)
			if err != nil {
				return nil, err
			}
			groupByID := make(map[int64]*iamentity.Group, len(groups.Items))
			for _, group := range groups.Items {
				groupByID[group.ID] = group
			}
			for _, link := range groups.Links {
				if group := groupByID[link.TargetID]; group != nil {
					byID[link.SourceID].Groups = append(byID[link.SourceID].Groups, *group)
				}
			}
			roleByID := make(map[int64]*iamentity.Role, len(roles.Items))
			for _, role := range roles.Items {
				roleByID[role.ID] = role
			}
			for _, link := range roles.Links {
				if role := roleByID[link.TargetID]; role != nil {
					byID[link.SourceID].Roles = append(byID[link.SourceID].Roles, *role)
				}
			}
			return users, nil
		}})
	return err
}

func (s *UserService) bindHTTPList(options appcrud.Options[*iamentity.User, int64], grants []*app.CommandGrant) (*userHTTPListAccess, error) {
	if len(grants) != 3 {
		return nil, errors.NewCode(errors.InvalidInput, "user HTTP list requires all three resources")
	}
	for i, name := range []string{"users", "groups", "roles"} {
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "user HTTP list grant differs from its declaration")
		}
		request, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		action := "http_list_" + name
		_, resource := s.directoryProvider(name)
		if name == "users" {
			action, resource = appcrud.ActionList, "user"
		}
		if request.Action != action || request.Resource != resource {
			return nil, errors.NewCode(errors.InvalidInput, "user HTTP list action differs from its declaration")
		}
	}
	known := map[int64]bool{}
	reader, err := app.NewCommandReader(s.userRepo.Repo, grants[0], func(ctx context.Context, in userHTTPListQuery, condition spec.Spec) ([]*iamentity.User, error) {
		users, err := s.userRepo.Repo.Query(ctx, in.Options, spec.And(condition, in.Condition))
		if err != nil {
			return nil, err
		}
		for _, user := range users {
			if user == nil || user.ID <= 0 {
				return nil, errors.NewCode(errors.Forbidden, "user query returned an invalid association source")
			}
			known[user.ID] = true
		}
		return users, nil
	})
	if err != nil {
		return nil, err
	}
	access := &userHTTPListAccess{}
	access.users, err = appcrud.NewReadApplication[*iamentity.User, int64](&userHTTPListRepository{Repo: s.userRepo.Repo, users: reader}, options)
	if err != nil {
		return nil, err
	}
	access.groups, err = app.NewCommandReader(s.groupRepo.Repo, grants[1], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
		if err := requireAssociationSources(ids, known); err != nil {
			return relations.Catalog[*iamentity.Group]{}, err
		}
		return s.groupRepo.GroupsForUsers(ctx, ids, condition)
	})
	if err != nil {
		return nil, err
	}
	access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[2], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
		if err := requireAssociationSources(ids, known); err != nil {
			return relations.Catalog[*iamentity.Role]{}, err
		}
		return s.roleRepo.RolesForUsers(ctx, ids, condition)
	})
	return access, err
}

func (s *UserService) QueryHTTP(ctx context.Context, options query.QueryOptions) ([]*iamentity.User, error) {
	return s.httpListCommand.Execute(ctx, options)
}

func (s *UserService) QueryCountHTTP(ctx context.Context, options query.QueryOptions) (int64, error) {
	return s.httpListCounts.QueryCount(ctx, options)
}

func (s *UserService) ListAuthorizationBinding() (auth.EntryBinding, error) {
	if s == nil || s.httpListCommand == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user HTTP list command is required")
	}
	return s.httpListCommand.AuthorizationBinding()
}
