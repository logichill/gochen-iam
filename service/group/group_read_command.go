package group

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type GroupReadInput struct {
	ID    int64
	Level int
}
type GroupReadResult struct {
	Groups []*iamentity.Group
	Users  []*iamentity.User
	Roles  []*iamentity.Role
}
type groupLookup struct {
	Operation     string
	IDs           []int64
	Level, Offset int
}
type groupReadAccess struct {
	group      *app.CommandRepository[*iamentity.Group, int64]
	groups     *app.CommandReader[groupLookup, []*iamentity.Group]
	members    *app.CommandReader[[]int64, relations.Catalog[*iamentity.User]]
	userGroups *app.CommandReader[[]int64, relations.Catalog[*iamentity.Group]]
	roles      *app.CommandReader[[]int64, relations.Catalog[*iamentity.Role]]
	scopes     *app.CommandReader[[]int64, []*iamentity.Scope]
}
type groupReadCommand = app.Command[GroupReadInput, *groupReadAccess, GroupReadResult]

func (s *GroupService) compileReadCommands() error {
	var err error
	s.roleNamespaces, err = ormrepo.NewRepo[*iamentity.Scope, int64](s.roleRepo.Orm(), "scopes",
		ormrepo.WithResourceKind[*iamentity.Scope, int64]("iam.group.role_namespace"), ormrepo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""))
	if err != nil {
		return err
	}
	s.readCommands = map[string]*groupReadCommand{}
	for _, base := range []string{"roots", "by_level", "users", "roles"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			names := []string{"groups"}
			switch base {
			case "roots":
				names = append(names, "members", "roles")
			case "by_level":
				names = append(names, "members")
			case "users":
				names = append(names, "members", "user_groups", "roles")
			case "roles":
				names = append(names, "roles", "scopes")
			}
			resources := make([]app.CommandResource[GroupReadInput], 0, len(names))
			for _, name := range names {
				provider, resource := s.readProvider(name)
				var policies []auth.IPolicy
				if prefix != "" {
					policies = []auth.IPolicy{groupAssociationEntryPolicy{}}
				}
				descriptor := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindList, Permission: svc.GroupPermissionSet.Code(iamperm.ActionRead)}}}
				var authorizer *auth.Authorizer
				if name == "scopes" {
					// Namespace reads derive from authorized roles. The bound reader
					// accepts only their actual NamespaceScopeIDs; Scope has no scope dimension.
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData,
						Rules: []auth.Rule{{ID: "iam.group.role_namespace.read", System: auth.SystemCheckConstraints,
							UnauthorizedAsDenial: true, Constraints: policies}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
				} else {
					authorizer, err = s.authorizer.Compile(descriptor, provider.ExecutionDescriptor().Metadata(), policies...)
				}
				if err != nil {
					return errors.Wrap(err, errors.InvalidInput, "compile group read "+action+" resource "+name)
				}
				resourceName := name
				resources = append(resources, app.CommandResource[GroupReadInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
					ConditionPath: "CommandReader/Repository -> trusted association sources -> actual " + resource + " with independent condition before join, projection and pagination",
					Intent: func(in GroupReadInput) (auth.Request, error) {
						if resourceName == "groups" && (base == "users" || base == "roles") {
							if in.ID <= 0 {
								return auth.Request{}, errors.NewCode(errors.InvalidInput, "group ID must be positive")
							}
							return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
						}
						return auth.Request{}, nil
					}})
			}
			command, err := app.NewCommand(app.CommandOptions[GroupReadInput, *groupReadAccess, GroupReadResult]{Resources: resources,
				Access: func(_ context.Context, in GroupReadInput, grants []*app.CommandGrant) (*groupReadAccess, error) {
					return s.bindReadAccess(action, names, in, grants)
				},
				Handler: func(ctx context.Context, in GroupReadInput, access *groupReadAccess) (GroupReadResult, error) {
					return executeGroupRead(ctx, base, in, access)
				}})
			if err != nil {
				return err
			}
			s.readCommands[action] = command
		}
	}
	return nil
}

func (s *GroupService) readProvider(name string) (app.IExecutionDescriptorProvider, string) {
	switch name {
	case "members":
		return s.userRepo, svc.UserResourceKind
	case "roles":
		return s.roleRepo, svc.RoleResourceKind
	case "scopes":
		return s.roleNamespaces, "iam.group.role_namespace"
	default:
		return s.groupRepo, svc.GroupResourceKind
	}
}

func requireKnownSources(ids []int64, known map[int64]bool) error {
	for _, id := range ids {
		if !known[id] {
			return errors.NewCode(errors.Forbidden, "association source is outside the authorized resources")
		}
	}
	return nil
}

func (s *GroupService) bindReadAccess(action string, names []string, in GroupReadInput, grants []*app.CommandGrant) (*groupReadAccess, error) {
	access := &groupReadAccess{}
	if len(grants) != len(names) {
		return nil, errors.NewCode(errors.InvalidInput, "group read requires every resource grant")
	}
	base := strings.TrimPrefix(action, "http_")
	knownGroups, knownParents, knownUsers, knownScopes := map[int64]bool{}, map[int64]bool{}, map[int64]bool{}, map[int64]bool{}
	for i, name := range names {
		provider, resource := s.readProvider(name)
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "group read grant differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if req.Resource != resource || req.Action != action+"_"+name {
			return nil, errors.NewCode(errors.InvalidInput, "group read action differs from its declaration")
		}
		switch name {
		case "groups":
			if base == "users" || base == "roles" {
				access.group, err = app.NewCommandRepository(s.groupRepo, grants[i])
				if err == nil {
					access.groups, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, lookup groupLookup, condition spec.Spec) ([]*iamentity.Group, error) {
						if lookup.Operation != "target" || len(lookup.IDs) != 1 || lookup.IDs[0] != in.ID {
							return nil, errors.NewCode(errors.Forbidden, "group read target differs from its intent")
						}
						group, err := access.group.Get(ctx, in.ID)
						if err != nil {
							return nil, err
						}
						knownGroups[group.GetID()] = true
						return []*iamentity.Group{group}, nil
					})
				}
			} else {
				access.groups, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, lookup groupLookup, condition spec.Spec) ([]*iamentity.Group, error) {
					if lookup.Offset < 0 {
						return nil, errors.NewCode(errors.InvalidInput, "group page offset must be nonnegative")
					}
					switch lookup.Operation {
					case "roots":
						if base != "roots" {
							return nil, errors.NewCode(errors.Forbidden, "root lookup is outside the group read action")
						}
						condition = spec.And(condition, spec.IsNull(meta.ByField("ParentID")))
					case "children":
						if base != "roots" {
							return nil, errors.NewCode(errors.Forbidden, "child lookup is outside the group read action")
						}
						if err := requireKnownSources(lookup.IDs, knownGroups); err != nil {
							return nil, err
						}
						values := make([]any, 0, len(lookup.IDs))
						for _, id := range lookup.IDs {
							values = append(values, id)
						}
						condition = spec.And(condition, spec.In(meta.ByField("ParentID"), values...))
					case "by_level":
						if base != "by_level" || lookup.Level != in.Level {
							return nil, errors.NewCode(errors.Forbidden, "level lookup is outside the group read action")
						}
						condition = spec.And(condition, spec.Eq(meta.ByField("Level"), in.Level))
					case "parents":
						if base != "by_level" {
							return nil, errors.NewCode(errors.Forbidden, "parent lookup is outside the group read action")
						}
						if err := requireKnownSources(lookup.IDs, knownParents); err != nil {
							return nil, err
						}
						values := make([]any, 0, len(lookup.IDs))
						for _, id := range lookup.IDs {
							values = append(values, id)
						}
						condition = spec.And(condition, spec.In(meta.ID(), values...))
					default:
						return nil, errors.NewCode(errors.InvalidInput, "group lookup is not declared")
					}
					items, err := s.groupRepo.Query(ctx, query.QueryOptions{Offset: lookup.Offset, Limit: 1000, Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}}, condition)
					if err != nil {
						return nil, err
					}
					for _, group := range items {
						knownGroups[group.GetID()] = true
						if lookup.Operation == "by_level" && group.ParentID != nil {
							knownParents[*group.ParentID] = true
						}
					}
					return items, nil
				})
			}
		case "members":
			access.members, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
				if err := requireKnownSources(ids, knownGroups); err != nil {
					return relations.Catalog[*iamentity.User]{}, err
				}
				catalog, err := s.userRepo.MembersForGroups(ctx, ids, condition)
				if err == nil {
					for _, user := range catalog.Items {
						knownUsers[user.GetID()] = true
					}
				}
				return catalog, err
			})
		case "user_groups":
			access.userGroups, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
				if err := requireKnownSources(ids, knownUsers); err != nil {
					return relations.Catalog[*iamentity.Group]{}, err
				}
				return s.groupRepo.GroupsForUsers(ctx, ids, condition)
			})
		case "roles":
			access.roles, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
				var catalog relations.Catalog[*iamentity.Role]
				var err error
				if base == "users" {
					if err = requireKnownSources(ids, knownUsers); err == nil {
						catalog, err = s.roleRepo.RolesForUsers(ctx, ids, condition)
					}
				} else {
					if err = requireKnownSources(ids, knownGroups); err == nil {
						catalog, err = s.roleRepo.RolesForGroups(ctx, ids, condition)
					}
				}
				if err == nil {
					for _, role := range catalog.Items {
						if role.NamespaceScopeID > 0 {
							knownScopes[role.NamespaceScopeID] = true
						}
					}
				}
				return catalog, err
			})
		case "scopes":
			access.scopes, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) ([]*iamentity.Scope, error) {
				if err := requireKnownSources(ids, knownScopes); err != nil {
					return nil, err
				}
				var scopes []*iamentity.Scope
				for start := 0; start < len(ids); start += 1000 {
					values := make([]any, 0, 1000)
					for _, id := range ids[start:min(start+1000, len(ids))] {
						values = append(values, id)
					}
					items, err := s.roleNamespaces.Query(ctx, query.QueryOptions{Limit: 1000}, spec.And(condition, spec.In(meta.ID(), values...)))
					if err != nil {
						return nil, err
					}
					scopes = append(scopes, items...)
				}
				return scopes, nil
			})
		}
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func executeGroupRead(ctx context.Context, base string, in GroupReadInput, access *groupReadAccess) (GroupReadResult, error) {
	var out GroupReadResult
	if base == "users" || base == "roles" {
		if _, err := access.groups.Read(ctx, groupLookup{Operation: "target", IDs: []int64{in.ID}}); err != nil {
			return out, err
		}
		if base == "roles" {
			roles, err := access.roles.Read(ctx, []int64{in.ID})
			if err != nil {
				return out, err
			}
			ids := make([]int64, 0, len(roles.Items))
			for _, role := range roles.Items {
				if role.NamespaceScopeID > 0 {
					ids = append(ids, role.NamespaceScopeID)
				}
			}
			scopes, err := access.scopes.Read(ctx, ids)
			if err != nil {
				return out, err
			}
			byID := map[int64]*iamentity.Scope{}
			for _, scope := range scopes {
				byID[scope.GetID()] = scope
			}
			for _, role := range roles.Items {
				role.NamespaceScope = byID[role.NamespaceScopeID]
			}
			out.Roles = roles.Items
			return out, nil
		}
		members, err := access.members.Read(ctx, []int64{in.ID})
		if err != nil {
			return out, err
		}
		ids := make([]int64, 0, len(members.Items))
		users := map[int64]*iamentity.User{}
		for _, user := range members.Items {
			ids = append(ids, user.GetID())
			users[user.GetID()] = user
			user.Groups = []iamentity.Group{}
			user.Roles = []iamentity.Role{}
		}
		groups, err := access.userGroups.Read(ctx, ids)
		if err != nil {
			return out, err
		}
		groupMap := map[int64]*iamentity.Group{}
		for _, group := range groups.Items {
			groupMap[group.GetID()] = group
		}
		for _, link := range groups.Links {
			if group := groupMap[link.TargetID]; group != nil && users[link.SourceID] != nil {
				users[link.SourceID].Groups = append(users[link.SourceID].Groups, *group)
			}
		}
		roles, err := access.roles.Read(ctx, ids)
		if err != nil {
			return out, err
		}
		roleMap := map[int64]*iamentity.Role{}
		for _, role := range roles.Items {
			roleMap[role.GetID()] = role
		}
		for _, link := range roles.Links {
			if role := roleMap[link.TargetID]; role != nil && users[link.SourceID] != nil {
				users[link.SourceID].Roles = append(users[link.SourceID].Roles, *role)
			}
		}
		out.Users = members.Items
		return out, nil
	}
	for offset := 0; ; offset += 1000 {
		items, err := access.groups.Read(ctx, groupLookup{Operation: base, Level: in.Level, Offset: offset})
		if err != nil {
			return out, err
		}
		ids := make([]int64, 0, len(items))
		byID := map[int64]*iamentity.Group{}
		for _, group := range items {
			ids = append(ids, group.GetID())
			byID[group.GetID()] = group
		}
		members, err := access.members.Read(ctx, ids)
		if err != nil {
			return out, err
		}
		userMap := map[int64]*iamentity.User{}
		for _, user := range members.Items {
			userMap[user.GetID()] = user
		}
		for _, link := range members.Links {
			if user := userMap[link.TargetID]; user != nil && byID[link.SourceID] != nil {
				byID[link.SourceID].Users = append(byID[link.SourceID].Users, user)
			}
		}
		if base == "roots" {
			for childOffset := 0; ; childOffset += 1000 {
				children, err := access.groups.Read(ctx, groupLookup{Operation: "children", IDs: ids, Offset: childOffset})
				if err != nil {
					return out, err
				}
				for _, child := range children {
					if child.ParentID != nil && byID[*child.ParentID] != nil {
						byID[*child.ParentID].Children = append(byID[*child.ParentID].Children, child)
					}
				}
				if len(children) < 1000 {
					break
				}
			}
			roles, err := access.roles.Read(ctx, ids)
			if err != nil {
				return out, err
			}
			roleMap := map[int64]*iamentity.Role{}
			for _, role := range roles.Items {
				roleMap[role.GetID()] = role
			}
			for _, link := range roles.Links {
				if role := roleMap[link.TargetID]; role != nil && byID[link.SourceID] != nil {
					byID[link.SourceID].DefaultRoles = append(byID[link.SourceID].DefaultRoles, role)
				}
			}
		} else {
			parentIDs := make([]int64, 0, len(items))
			for _, group := range items {
				if group.ParentID != nil {
					parentIDs = append(parentIDs, *group.ParentID)
				}
			}
			parents, err := access.groups.Read(ctx, groupLookup{Operation: "parents", IDs: parentIDs})
			if err != nil {
				return out, err
			}
			parentMap := map[int64]*iamentity.Group{}
			for _, parent := range parents {
				parentMap[parent.GetID()] = parent
			}
			for _, group := range items {
				if group.ParentID != nil {
					group.Parent = parentMap[*group.ParentID]
				}
			}
		}
		out.Groups = append(out.Groups, items...)
		if len(items) < 1000 {
			break
		}
	}
	return out, nil
}

func (s *GroupService) executeRead(ctx context.Context, action string, in GroupReadInput) (GroupReadResult, error) {
	command := s.readCommands[action]
	if command == nil {
		return GroupReadResult{}, errors.NewCode(errors.InvalidInput, "group read action is not declared")
	}
	return command.Execute(ctx, in)
}
func (s *GroupService) ExecuteReadHTTP(ctx context.Context, action string, in GroupReadInput) (GroupReadResult, error) {
	return s.executeRead(ctx, "http_"+action, in)
}
func (s *GroupService) ReadAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.readCommands["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "group read HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
