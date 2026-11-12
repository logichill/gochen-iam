package role

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
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

type roleDirectoryInput struct {
	ID      int64
	Query   query.QueryOptions
	Keyword string
	Count   bool
}
type roleDirectoryResult struct {
	Items []*iamentity.Role
	Count int64
}
type roleDirectoryAccess struct {
	roles      *app.CommandReader[roleDirectoryInput, roleDirectoryResult]
	namespaces *app.CommandReader[[]int64, []*iamentity.Scope]
	users      *app.CommandReader[[]int64, relations.Catalog[*iamentity.User]]
	groups     *app.CommandReader[[]int64, relations.Catalog[*iamentity.Group]]
}
type roleDirectoryCommand = app.Command[roleDirectoryInput, *roleDirectoryAccess, roleDirectoryResult]

func (s *RoleService) compileDirectoryCommands() error {
	scopes, err := ormrepo.NewRepo[*iamentity.Scope, int64](s.roleRepo.Orm(), "scopes", ormrepo.WithResourceKind[*iamentity.Scope, int64]("iam.role.directory_namespace"), ormrepo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""))
	if err != nil {
		return err
	}
	s.directoryCommands = map[string]*roleDirectoryCommand{}
	coverage, err := auth.NewFact("iam.role.directory_coverage", func(ctx context.Context, _ auth.Request) (roleReadCoverage, error) {
		tenant, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return roleReadCoverage{}, err
		}
		if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, "role:api:read", tenant); err != nil {
			return roleReadCoverage{}, err
		}
		return roleReadCoverage{TenantID: tenant}, nil
	})
	if err != nil {
		return err
	}
	for _, base := range []string{"read", "list", "search", "active"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			fullDirectory := base == "search" || base == "active"
			var guards []auth.IPolicy
			if prefix != "" {
				guards = []auth.IPolicy{roleHTTPEntryPolicy{}}
			}
			resources := []app.CommandResource[roleDirectoryInput]{}
			names := []string{"roles", "namespaces"}
			if fullDirectory {
				names = append(names, "users", "groups")
			}
			for _, name := range names {
				provider := app.IExecutionDescriptorProvider(s.roleRepo.Repo)
				resource := svc.RoleResourceKind
				if name == "namespaces" {
					provider = scopes
					resource = "iam.role.directory_namespace"
				}
				if name == "users" {
					provider, resource = s.userRepo, "iam.role.directory_users"
				}
				if name == "groups" {
					provider, resource = s.groupRepo, "iam.role.directory_groups"
				}
				d := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindList, Permission: "role:api:read"}}}
				var authorizer *auth.Authorizer
				if fullDirectory {
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: resource, System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{roleSystemPolicy{coverage: coverage, http: prefix != ""}}}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
				} else if name == "roles" {
					authorizer, err = s.authorizer.Compile(d, provider.ExecutionDescriptor().Metadata(), guards...)
				} else {
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
				}
				if err != nil {
					return err
				}
				isRole := name == "roles"
				resources = append(resources, app.CommandResource[roleDirectoryInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
					ConditionPath: "CommandReader -> role scope before query/count; namespace IDs derive only from returned authorized roles",
					Intent: func(in roleDirectoryInput) (auth.Request, error) {
						if isRole && base == "read" {
							if in.ID <= 0 {
								return auth.Request{}, errors.NewCode(errors.InvalidInput, "role ID must be positive")
							}
							return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
						}
						return auth.Request{}, nil
					}})
				if fullDirectory && name != "roles" {
					resources[len(resources)-1].ReuseFactsFrom = "roles"
				}
			}
			command, err := app.NewCommand(app.CommandOptions[roleDirectoryInput, *roleDirectoryAccess, roleDirectoryResult]{Resources: resources,
				Access: func(_ context.Context, _ roleDirectoryInput, grants []*app.CommandGrant) (*roleDirectoryAccess, error) {
					var err error
					if len(grants) != len(names) {
						return nil, errors.NewCode(errors.InvalidInput, "role directory requires its resource grants")
					}
					for i, name := range names {
						if grants[i] == nil || grants[i].Name() != name {
							return nil, errors.NewCode(errors.InvalidInput, "role directory grant differs from declaration")
						}
					}
					known := map[int64]bool{}
					knownRoles := map[int64]bool{}
					access := &roleDirectoryAccess{}
					access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[0], func(ctx context.Context, in roleDirectoryInput, condition spec.Spec) (roleDirectoryResult, error) {
						var result roleDirectoryResult
						tenant, err := svc.TenantIDFromContext(ctx)
						if err != nil {
							return result, err
						}
						condition = spec.And(condition, spec.Eq(meta.ByField("TenantID"), tenant))
						if in.Count {
							result.Count, err = s.roleRepo.Repo.QueryCount(ctx, in.Query, condition)
							return result, err
						}
						switch base {
						case "read":
							item, e := s.roleRepo.Repo.Get(ctx, in.ID, condition)
							err = e
							if e == nil {
								if e := requireRoleOwnership(ctx, item); e != nil {
									return result, e
								}
								result.Items = []*iamentity.Role{item}
							}
						case "search":
							result.Items, err = s.roleRepo.SearchRoles(ctx, in.Keyword, in.Query.Limit, condition)
						default:
							if base == "active" {
								condition = spec.And(condition, spec.Eq(meta.ByField("Status"), svc.RoleStatusActive))
								for offset := 0; ; offset += 1000 {
									items, e := s.roleRepo.Repo.Query(ctx, query.QueryOptions{Offset: offset, Limit: 1000, Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}}, condition)
									if e != nil {
										return result, e
									}
									result.Items = append(result.Items, items...)
									if len(items) < 1000 {
										break
									}
								}
							} else {
								result.Items, err = s.roleRepo.Repo.Query(ctx, in.Query, condition)
							}
						}
						if err != nil {
							return result, err
						}
						for _, item := range result.Items {
							knownRoles[item.ID] = true
							if item.NamespaceScopeID > 0 {
								known[item.NamespaceScopeID] = true
							}
						}
						return result, nil
					})
					if err != nil {
						return nil, err
					}
					access.namespaces, err = app.NewCommandReader(scopes, grants[1], func(ctx context.Context, ids []int64, condition spec.Spec) ([]*iamentity.Scope, error) {
						values := []any{}
						seen := map[int64]bool{}
						for _, id := range ids {
							if !known[id] {
								return nil, errors.NewCode(errors.Forbidden, "namespace differs from trusted directory")
							}
							if !seen[id] {
								values = append(values, id)
								seen[id] = true
							}
						}
						items := []*iamentity.Scope{}
						for start := 0; start < len(values); start += 1000 {
							batch, err := scopes.Query(ctx, query.QueryOptions{Limit: 1000}, spec.And(condition, spec.In(meta.ID(), values[start:min(start+1000, len(values))]...)))
							if err != nil {
								return nil, err
							}
							items = append(items, batch...)
						}
						return items, nil
					})
					if err != nil {
						return nil, err
					}
					if fullDirectory {
						check := func(ids []int64) error {
							for _, id := range ids {
								if !knownRoles[id] {
									return errors.NewCode(errors.Forbidden, "relation source differs from trusted role directory")
								}
							}
							return nil
						}
						access.users, err = app.NewCommandReader(s.userRepo, grants[2], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.User], error) {
							if err := check(ids); err != nil {
								return relations.Catalog[*iamentity.User]{}, err
							}
							return s.userRepo.MembersForRoles(ctx, ids, condition)
						})
						if err != nil {
							return nil, err
						}
						access.groups, err = app.NewCommandReader(s.groupRepo, grants[3], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
							if err := check(ids); err != nil {
								return relations.Catalog[*iamentity.Group]{}, err
							}
							return s.groupRepo.GroupsForRoles(ctx, ids, condition)
						})
					}
					return access, err
				}, Handler: func(ctx context.Context, in roleDirectoryInput, access *roleDirectoryAccess) (roleDirectoryResult, error) {
					result, err := access.roles.Read(ctx, in)
					if err != nil {
						return result, err
					}
					ids := []int64{}
					for _, item := range result.Items {
						if item.NamespaceScopeID > 0 {
							ids = append(ids, item.NamespaceScopeID)
						}
					}
					namespaces, err := access.namespaces.Read(ctx, ids)
					if err != nil {
						return roleDirectoryResult{}, err
					}
					byID := map[int64]*iamentity.Scope{}
					for _, scope := range namespaces {
						byID[scope.ID] = scope
					}
					for _, item := range result.Items {
						item.NamespaceScope = byID[item.NamespaceScopeID]
					}
					if fullDirectory && len(result.Items) > 0 {
						roleIDs := []int64{}
						byRole := map[int64]*iamentity.Role{}
						for _, item := range result.Items {
							roleIDs = append(roleIDs, item.ID)
							byRole[item.ID] = item
						}
						users, err := access.users.Read(ctx, roleIDs)
						if err != nil {
							return roleDirectoryResult{}, err
						}
						groups, err := access.groups.Read(ctx, roleIDs)
						if err != nil {
							return roleDirectoryResult{}, err
						}
						userMap := map[int64]*iamentity.User{}
						for _, u := range users.Items {
							userMap[u.ID] = u
						}
						groupMap := map[int64]*iamentity.Group{}
						for _, g := range groups.Items {
							groupMap[g.ID] = g
						}
						for _, link := range users.Links {
							if r, u := byRole[link.SourceID], userMap[link.TargetID]; r != nil && u != nil {
								r.Users = append(r.Users, iamentity.User{
									Entity: u.Entity, Timestamps: u.Timestamps, DeletedAt: u.DeletedAt,
									TenantID: u.TenantID, HomeTenantID: u.HomeTenantID, HomeScopeID: u.HomeScopeID,
									ManagedScopeID: u.ManagedScopeID, OwnerID: u.OwnerID, Username: u.Username,
									Email: u.Email, Password: u.Password, Status: u.Status, Avatar: u.Avatar,
									LastLoginAt: u.LastLoginAt, Groups: u.Groups, Roles: u.Roles,
								})
							}
						}
						for _, link := range groups.Links {
							if r, g := byRole[link.SourceID], groupMap[link.TargetID]; r != nil && g != nil {
								r.Groups = append(r.Groups, *g)
							}
						}
					}
					return result, nil
				}})
			if err != nil {
				return err
			}
			s.directoryCommands[action] = command
		}
	}
	return nil
}

func (a *roleCRUDApplication) directoryAction(base string) string {
	if a == a.service.httpCRUDApplication {
		return "http_" + base
	}
	return base
}
func (a *roleCRUDApplication) Get(ctx context.Context, id int64) (*iamentity.Role, error) {
	result, err := a.service.directoryCommands[a.directoryAction("read")].Execute(ctx, roleDirectoryInput{ID: id})
	if err != nil {
		return nil, err
	}
	return result.Items[0], nil
}
func (a *roleCRUDApplication) List(ctx context.Context, offset, limit int) ([]*iamentity.Role, error) {
	return a.Query(ctx, query.QueryOptions{Offset: offset, Limit: limit})
}
func (a *roleCRUDApplication) Query(ctx context.Context, options query.QueryOptions) ([]*iamentity.Role, error) {
	if options.Offset < 0 {
		options.Offset = 0
	}
	if options.Limit <= 0 || options.Limit > a.MaxPageSize() {
		options.Limit = a.MaxPageSize()
	}
	result, err := a.service.directoryCommands[a.directoryAction("list")].Execute(ctx, roleDirectoryInput{Query: options})
	return result.Items, err
}
func (a *roleCRUDApplication) Count(ctx context.Context) (int64, error) {
	return a.QueryCount(ctx, query.QueryOptions{})
}
func (a *roleCRUDApplication) QueryCount(ctx context.Context, options query.QueryOptions) (int64, error) {
	result, err := a.service.directoryCommands[a.directoryAction("list")].Execute(ctx, roleDirectoryInput{Query: options, Count: true})
	return result.Count, err
}
