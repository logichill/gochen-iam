package role

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleUsersAccess struct {
	source *app.CommandReader[struct{}, *iamentity.Role]
	users  *app.CommandReader[int64, relations.Catalog[*iamentity.User]]
	groups *app.CommandReader[[]int64, relations.Catalog[*iamentity.Group]]
	roles  *app.CommandReader[[]int64, relations.Catalog[*iamentity.Role]]
}
type roleUsersCommand = app.Command[int64, *roleUsersAccess, []*iamentity.User]
type roleGroupsAccess struct {
	source *app.CommandReader[struct{}, *iamentity.Role]
	groups *app.CommandReader[int64, relations.Catalog[*iamentity.Group]]
}
type roleGroupsCommand = app.Command[int64, *roleGroupsAccess, []*iamentity.Group]

func roleMemberIntent(id int64) (auth.Request, error) {
	if id <= 0 {
		return auth.Request{}, errors.NewCode(errors.InvalidInput, "role ID must be positive")
	}
	return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
}

func (s *RoleService) compileRoleUsersCommand() error {
	target, err := auth.NewFact("iam.role.users_source", func(ctx context.Context, req auth.Request) (*iamentity.Role, error) {
		if req.Resource != svc.RoleResourceKind || req.Action != "users" || len(req.IDs) != 1 {
			return nil, errors.NewCode(errors.InvalidInput, "role users requires one declared source")
		}
		id, err := strconv.ParseInt(req.IDs[0], 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.NewCode(errors.InvalidInput, "role ID must be positive")
		}
		return s.roleRepo.Repo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	resources := []app.CommandResource[int64]{}
	for _, name := range []string{"role", "users", "groups", "member_roles"} {
		provider, resource, action, kind := app.IExecutionDescriptorProvider(s.roleRepo.Repo), svc.RoleResourceKind, "users", auth.KindRead
		var constraints []auth.IPolicy
		switch name {
		case "role":
			constraints = []auth.IPolicy{roleUsersSourcePolicy{service: s, target: target}}
		case "users":
			provider, resource, action, kind = s.userRepo, "iam.role.users_user", "users_users", auth.KindList
			constraints = []auth.IPolicy{roleMemberScopePolicy{}}
		case "groups":
			provider, resource, action, kind = s.groupRepo, "iam.role.users_group", "users_groups", auth.KindList
			constraints = []auth.IPolicy{roleMemberScopePolicy{}}
		case "member_roles":
			action, kind = "users_member_roles", auth.KindList
		}
		descriptor := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action, Kind: kind, Permission: "role:api:read"}}}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.role." + action, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: constraints}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
		if err != nil {
			return err
		}
		intent := func(int64) (auth.Request, error) { return auth.Request{}, nil }
		if name == "role" {
			intent = roleMemberIntent
		}
		resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: action, Intent: intent,
			ConditionPath: "CommandReader -> frozen source role Fact; members under user scope; nested groups under group scope; roles derived only from actual returned user relations"})
	}
	s.usersCommand, err = app.NewCommand(app.CommandOptions[int64, *roleUsersAccess, []*iamentity.User]{Resources: resources,
		Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (*roleUsersAccess, error) {
			return s.bindRoleUsers(id, target, grants)
		},
		Handler: func(ctx context.Context, id int64, a *roleUsersAccess) ([]*iamentity.User, error) {
			if _, err := a.source.Read(ctx, struct{}{}); err != nil {
				return nil, err
			}
			users, err := a.users.Read(ctx, id)
			if err != nil {
				return nil, err
			}
			ids := make([]int64, 0, len(users.Items))
			byID := map[int64]*iamentity.User{}
			for _, u := range users.Items {
				ids = append(ids, u.ID)
				byID[u.ID] = u
			}
			groups, err := a.groups.Read(ctx, ids)
			if err != nil {
				return nil, err
			}
			groupMap := map[int64]*iamentity.Group{}
			for _, g := range groups.Items {
				groupMap[g.ID] = g
			}
			for _, link := range groups.Links {
				if u, g := byID[link.SourceID], groupMap[link.TargetID]; u != nil && g != nil {
					u.Groups = append(u.Groups, *g)
				}
			}
			roles, err := a.roles.Read(ctx, ids)
			if err != nil {
				return nil, err
			}
			roleMap := map[int64]*iamentity.Role{}
			for _, r := range roles.Items {
				roleMap[r.ID] = r
			}
			for _, link := range roles.Links {
				if u, r := byID[link.SourceID], roleMap[link.TargetID]; u != nil && r != nil {
					u.Roles = append(u.Roles, *r)
				}
			}
			return users.Items, nil
		}})
	return err
}

func (s *RoleService) bindRoleUsers(id int64, target *auth.Fact[*iamentity.Role], grants []*app.CommandGrant) (*roleUsersAccess, error) {
	if err := validateRoleMemberGrants("users", id, []string{"role", "users", "groups", "member_roles"}, grants); err != nil {
		return nil, err
	}
	a := &roleUsersAccess{}
	source, err := app.NewCommandRepository(s.roleRepo.Repo, grants[0])
	if err != nil {
		return nil, err
	}
	ready := false
	knownUsers := map[int64]bool{}
	a.source, err = app.NewCommandReader(s.roleRepo.Repo, grants[0], func(ctx context.Context, _ struct{}, _ spec.Spec) (*iamentity.Role, error) {
		role, err := source.FromFact(ctx, target)
		if err != nil {
			return nil, err
		}
		ready = true
		return role, nil
	})
	if err != nil {
		return nil, err
	}
	a.users, err = app.NewCommandReader(s.userRepo, grants[1], func(ctx context.Context, roleID int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
		if !ready || roleID != id {
			return relations.Catalog[*iamentity.User]{}, errors.NewCode(errors.Forbidden, "members require the trusted source role")
		}
		members, err := s.userRepo.MembersForRoles(ctx, []int64{roleID}, condition)
		if err != nil {
			return members, err
		}
		for _, u := range members.Items {
			knownUsers[u.ID] = true
		}
		return members, nil
	})
	if err != nil {
		return nil, err
	}
	checkUsers := func(ids []int64) error {
		for _, id := range ids {
			if !knownUsers[id] {
				return errors.NewCode(errors.Forbidden, "nested relation source differs from returned members")
			}
		}
		return nil
	}
	a.groups, err = app.NewCommandReader(s.groupRepo, grants[2], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
		if err := checkUsers(ids); err != nil {
			return relations.Catalog[*iamentity.Group]{}, err
		}
		return s.groupRepo.GroupsForUsers(ctx, ids, condition)
	})
	if err != nil {
		return nil, err
	}
	a.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[3], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
		if err := checkUsers(ids); err != nil {
			return relations.Catalog[*iamentity.Role]{}, err
		}
		return s.roleRepo.RolesForUsers(ctx, ids, condition)
	})
	return a, err
}

func (s *RoleService) compileRoleGroupsCommand() error {
	resources := []app.CommandResource[int64]{}
	for _, name := range []string{"role", "groups"} {
		provider, resource, action, kind := app.IExecutionDescriptorProvider(s.roleRepo.Repo), svc.RoleResourceKind, "groups", auth.KindRead
		intent := roleMemberIntent
		if name == "groups" {
			provider, resource, action, kind = s.groupRepo, svc.GroupResourceKind, "groups_groups", auth.KindList
			intent = func(int64) (auth.Request, error) { return auth.Request{}, nil }
		}
		authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action, Kind: kind, Permission: "role:api:read"}}}, provider.ExecutionDescriptor().Metadata())
		if err != nil {
			return err
		}
		resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: action, Intent: intent, ConditionPath: "CommandReader -> independently scoped source role -> actual group relations under group condition"})
	}
	var err error
	s.groupsCommand, err = app.NewCommand(app.CommandOptions[int64, *roleGroupsAccess, []*iamentity.Group]{Resources: resources,
		Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (*roleGroupsAccess, error) {
			return s.bindRoleGroups(id, grants)
		},
		Handler: func(ctx context.Context, id int64, a *roleGroupsAccess) ([]*iamentity.Group, error) {
			if _, err := a.source.Read(ctx, struct{}{}); err != nil {
				return nil, err
			}
			groups, err := a.groups.Read(ctx, id)
			return groups.Items, err
		}})
	return err
}

func (s *RoleService) bindRoleGroups(id int64, grants []*app.CommandGrant) (*roleGroupsAccess, error) {
	if err := validateRoleMemberGrants("groups", id, []string{"role", "groups"}, grants); err != nil {
		return nil, err
	}
	a := &roleGroupsAccess{}
	ready := false
	source, err := app.NewCommandRepository(s.roleRepo.Repo, grants[0])
	if err != nil {
		return nil, err
	}
	a.source, err = app.NewCommandReader(s.roleRepo.Repo, grants[0], func(ctx context.Context, _ struct{}, _ spec.Spec) (*iamentity.Role, error) {
		role, err := source.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if err := requireRoleOwnership(ctx, role); err != nil {
			return nil, err
		}
		ready = true
		return role, nil
	})
	if err != nil {
		return nil, err
	}
	a.groups, err = app.NewCommandReader(s.groupRepo, grants[1], func(ctx context.Context, roleID int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
		if !ready || roleID != id {
			return relations.Catalog[*iamentity.Group]{}, errors.NewCode(errors.Forbidden, "groups require the trusted source role")
		}
		return s.groupRepo.GroupsForRoles(ctx, []int64{roleID}, condition)
	})
	return a, err
}

func validateRoleMemberGrants(action string, id int64, names []string, grants []*app.CommandGrant) error {
	if id <= 0 || len(grants) != len(names) {
		return errors.NewCode(errors.InvalidInput, "role member grants are incomplete")
	}
	for i, name := range names {
		if grants[i] == nil || grants[i].Name() != name {
			return errors.NewCode(errors.InvalidInput, "role member grant differs from declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return err
		}
		expected := action + "_" + name
		if i == 0 {
			expected = action
		}
		if req.Action != expected || len(req.Targets) != 0 {
			return errors.NewCode(errors.InvalidInput, "role member action differs from declaration")
		}
		if i == 0 {
			if req.Resource != svc.RoleResourceKind || len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(id, 10) {
				return errors.NewCode(errors.InvalidInput, "role member source differs from declaration")
			}
		} else if len(req.IDs) != 0 {
			return errors.NewCode(errors.InvalidInput, "member targets must derive from trusted relations")
		}
	}
	return nil
}
