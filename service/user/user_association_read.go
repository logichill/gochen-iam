package user

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	ormrepo "gochen-runtime/db/orm/repo"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type UserAssociationReadInput struct{ ID int64 }
type UserAssociationReadResult struct {
	Groups []*iamentity.Group
	Roles  []*iamentity.Role
}
type userAssociationReadAccess struct {
	user    *app.CommandReader[int64, *iamentity.User]
	groups  *app.CommandReader[int64, relations.Catalog[*iamentity.Group]]
	parents *app.CommandReader[[]int64, []*iamentity.Group]
	members *app.CommandReader[[]int64, relations.Catalog[*iamentity.User]]
	roles   *app.CommandReader[[]int64, relations.Catalog[*iamentity.Role]]
	scopes  *app.CommandReader[[]int64, []*iamentity.Scope]
}
type userAssociationReadCommand = app.Command[UserAssociationReadInput, *userAssociationReadAccess, UserAssociationReadResult]

type userAssociationEntryPolicy struct{}

func (userAssociationEntryPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (userAssociationEntryPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	id, _ := strconv.ParseInt(principal.SubjectID, 10, 64)
	if id <= 0 {
		return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	kind := iamauth.ActiveScopeKindFromContext(ctx)
	if !iamtenant.CurrentContext(ctx).IsSingle() && kind != string(iamperm.ScopePlatform) && kind != string(iamperm.ScopeTenant) {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不允许访问此权限")
	}
	if !principal.AllowsPermission(svc.UserPermissionSet.Code(iamperm.ActionManage)) {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "权限不足")
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *UserService) compileAssociationReads() error {
	// Namespace is an existing relation of a visible role. Its declared provider
	// shares the actual role database, and its reader accepts only trusted IDs.
	namespaces, err := ormrepo.NewRepo[*iamentity.Scope, int64](s.roleRepo.Orm(), "scopes",
		ormrepo.WithResourceKind[*iamentity.Scope, int64]("iam.user.role_namespace"),
		ormrepo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""))
	if err != nil {
		return err
	}
	s.associationReads = map[string]*userAssociationReadCommand{}
	for _, base := range []string{"roles", "groups"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			names := []string{"user", "roles", "scopes"}
			if base == "groups" {
				names = []string{"user", "groups", "members", "roles"}
			}
			resources := make([]app.CommandResource[UserAssociationReadInput], 0, len(names))
			for _, name := range names {
				provider, resource := s.associationReadProvider(name, namespaces)
				var constraints []auth.IPolicy
				if prefix != "" {
					constraints = []auth.IPolicy{userAssociationEntryPolicy{}}
				}
				descriptor := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindList, Permission: svc.UserPermissionSet.Code(iamperm.ActionRead)}}}
				var authorizer *auth.Authorizer
				if name == "scopes" {
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData,
						Rules: []auth.Rule{{ID: "iam.user.role_namespace", System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: constraints}}},
						auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
				} else {
					authorizer, err = s.authorizer.Compile(descriptor, provider.ExecutionDescriptor().Metadata(), constraints...)
				}
				if err != nil {
					return err
				}
				resourceName := name
				resources = append(resources, app.CommandResource[UserAssociationReadInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
					ConditionPath: "CommandRepository/Reader -> authorized user -> trusted association IDs -> independent resource condition before JOIN and complete projections",
					Intent: func(in UserAssociationReadInput) (auth.Request, error) {
						if in.ID <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
						}
						if resourceName == "user" {
							return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
						}
						return auth.Request{}, nil
					}})
			}
			command, err := app.NewCommand(app.CommandOptions[UserAssociationReadInput, *userAssociationReadAccess, UserAssociationReadResult]{Resources: resources,
				Access: func(_ context.Context, in UserAssociationReadInput, grants []*app.CommandGrant) (*userAssociationReadAccess, error) {
					return s.bindAssociationRead(action, in, names, namespaces, grants)
				},
				Handler: func(ctx context.Context, in UserAssociationReadInput, access *userAssociationReadAccess) (UserAssociationReadResult, error) {
					return executeUserAssociationRead(ctx, base, in, access)
				}})
			if err != nil {
				return err
			}
			s.associationReads[action] = command
		}
	}
	return nil
}

func (s *UserService) associationReadProvider(name string, namespaces *ormrepo.Repo[*iamentity.Scope, int64]) (app.IExecutionDescriptorProvider, string) {
	switch name {
	case "groups":
		return s.groupRepo.Repo, svc.GroupResourceKind
	case "roles":
		return s.roleRepo.Repo, svc.RoleResourceKind
	case "scopes":
		return namespaces, "iam.user.role_namespace"
	default:
		return s.userRepo.Repo, svc.UserResourceKind
	}
}

func requireAssociationSources(ids []int64, known map[int64]bool) error {
	for _, id := range ids {
		if !known[id] {
			return errors.NewCode(errors.Forbidden, "association source differs from the authorized resource")
		}
	}
	return nil
}

func readKnownAssociationIDs[T domain.IEntity[int64]](ctx context.Context, repository *ormrepo.Repo[T, int64], ids []int64, known map[int64]bool, condition spec.Spec) ([]T, error) {
	if err := requireAssociationSources(ids, known); err != nil {
		return nil, err
	}
	var result []T
	seen := map[int64]bool{}
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			unique = append(unique, id)
			seen[id] = true
		}
	}
	for start := 0; start < len(unique); start += 1000 {
		values := make([]any, 0, 1000)
		for _, id := range unique[start:min(start+1000, len(unique))] {
			values = append(values, id)
		}
		items, err := repository.Query(ctx, query.QueryOptions{Limit: 1000}, spec.And(condition, spec.In(meta.ID(), values...)))
		if err != nil {
			return nil, err
		}
		result = append(result, items...)
	}
	return result, nil
}

func (s *UserService) bindAssociationRead(action string, in UserAssociationReadInput, names []string, namespaces *ormrepo.Repo[*iamentity.Scope, int64], grants []*app.CommandGrant) (*userAssociationReadAccess, error) {
	if len(grants) != len(names) {
		return nil, errors.NewCode(errors.InvalidInput, "user association read requires every grant")
	}
	access := &userAssociationReadAccess{}
	knownUser := false
	knownGroups, knownParents, knownScopes := map[int64]bool{}, map[int64]bool{}, map[int64]bool{}
	base := strings.TrimPrefix(action, "http_")
	for i, name := range names {
		provider, resource := s.associationReadProvider(name, namespaces)
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "user association grant differs from its declaration")
		}
		request, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if request.Resource != resource || request.Action != action+"_"+name {
			return nil, errors.NewCode(errors.InvalidInput, "user association action differs from its declaration")
		}
		switch name {
		case "user":
			var repository *app.CommandRepository[*iamentity.User, int64]
			repository, err = app.NewCommandRepository(s.userRepo.Repo, grants[i])
			if err == nil {
				access.user, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, id int64, _ spec.Spec) (*iamentity.User, error) {
					if id != in.ID {
						return nil, errors.NewCode(errors.Forbidden, "user differs from the requested association")
					}
					user, err := repository.Get(ctx, id)
					if err == nil {
						knownUser = true
					}
					return user, err
				})
			}
		case "groups":
			access.groups, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, id int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
				if id != in.ID || !knownUser {
					return relations.Catalog[*iamentity.Group]{}, errors.NewCode(errors.Forbidden, "group source differs from the requested user")
				}
				catalog, err := s.groupRepo.GroupsForUsers(ctx, []int64{id}, condition)
				if err == nil {
					for _, group := range catalog.Items {
						knownGroups[group.ID] = true
						if group.ParentID != nil {
							knownParents[*group.ParentID] = true
						}
					}
				}
				return catalog, err
			})
			if err == nil {
				access.parents, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) ([]*iamentity.Group, error) {
					return readKnownAssociationIDs(ctx, s.groupRepo.Repo, ids, knownParents, condition)
				})
			}
		case "members":
			access.members, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
				if err := requireAssociationSources(ids, knownGroups); err != nil {
					return relations.Catalog[*iamentity.User]{}, err
				}
				return s.userRepo.MembersForGroups(ctx, ids, condition)
			})
		case "roles":
			access.roles, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
				var catalog relations.Catalog[*iamentity.Role]
				var err error
				if base == "roles" {
					if len(ids) != 1 || ids[0] != in.ID || !knownUser {
						return catalog, errors.NewCode(errors.Forbidden, "role source differs from the requested user")
					}
					catalog, err = s.roleRepo.ActiveRolesForUser(ctx, in.ID, condition)
				} else {
					if err := requireAssociationSources(ids, knownGroups); err != nil {
						return catalog, err
					}
					catalog, err = s.roleRepo.RolesForGroups(ctx, ids, condition)
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
				return readKnownAssociationIDs(ctx, namespaces, ids, knownScopes, condition)
			})
		}
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func executeUserAssociationRead(ctx context.Context, base string, in UserAssociationReadInput, access *userAssociationReadAccess) (UserAssociationReadResult, error) {
	var result UserAssociationReadResult
	if _, err := access.user.Read(ctx, in.ID); err != nil {
		return result, err
	}
	if base == "roles" {
		catalog, err := access.roles.Read(ctx, []int64{in.ID})
		if err != nil {
			return result, err
		}
		ids := make([]int64, 0, len(catalog.Items))
		for _, role := range catalog.Items {
			if role.NamespaceScopeID > 0 {
				ids = append(ids, role.NamespaceScopeID)
			}
		}
		scopes, err := access.scopes.Read(ctx, ids)
		if err != nil {
			return result, err
		}
		byID := map[int64]*iamentity.Scope{}
		for _, scope := range scopes {
			byID[scope.ID] = scope
		}
		for _, role := range catalog.Items {
			role.NamespaceScope = byID[role.NamespaceScopeID]
		}
		result.Roles = catalog.Items
		return result, nil
	}
	catalog, err := access.groups.Read(ctx, in.ID)
	if err != nil {
		return result, err
	}
	ids, parentIDs := make([]int64, 0, len(catalog.Items)), make([]int64, 0, len(catalog.Items))
	groups := map[int64]*iamentity.Group{}
	for _, group := range catalog.Items {
		ids = append(ids, group.ID)
		groups[group.ID] = group
		if group.ParentID != nil {
			parentIDs = append(parentIDs, *group.ParentID)
		}
	}
	parents, err := access.parents.Read(ctx, parentIDs)
	if err != nil {
		return result, err
	}
	parentsByID := map[int64]*iamentity.Group{}
	for _, parent := range parents {
		parentsByID[parent.ID] = parent
	}
	for _, group := range catalog.Items {
		if group.ParentID != nil {
			group.Parent = parentsByID[*group.ParentID]
		}
	}
	members, err := access.members.Read(ctx, ids)
	if err != nil {
		return result, err
	}
	usersByID := map[int64]*iamentity.User{}
	for _, user := range members.Items {
		usersByID[user.ID] = user
	}
	for _, link := range members.Links {
		if user := usersByID[link.TargetID]; user != nil && groups[link.SourceID] != nil {
			groups[link.SourceID].Users = append(groups[link.SourceID].Users, user)
		}
	}
	roles, err := access.roles.Read(ctx, ids)
	if err != nil {
		return result, err
	}
	rolesByID := map[int64]*iamentity.Role{}
	for _, role := range roles.Items {
		rolesByID[role.ID] = role
	}
	for _, link := range roles.Links {
		if role := rolesByID[link.TargetID]; role != nil && groups[link.SourceID] != nil {
			groups[link.SourceID].DefaultRoles = append(groups[link.SourceID].DefaultRoles, role)
		}
	}
	result.Groups = catalog.Items
	return result, nil
}

func (s *UserService) executeAssociationRead(ctx context.Context, action string, in UserAssociationReadInput) (UserAssociationReadResult, error) {
	command := s.associationReads[action]
	if command == nil {
		return UserAssociationReadResult{}, errors.NewCode(errors.InvalidInput, "user association read action is not declared")
	}
	return command.Execute(ctx, in)
}

func (s *UserService) ExecuteAssociationReadHTTP(ctx context.Context, action string, in UserAssociationReadInput) (UserAssociationReadResult, error) {
	return s.executeAssociationRead(ctx, "http_"+action, in)
}

func (s *UserService) AssociationReadAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.associationReads["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user association HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
