package user

import (
	"context"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type userDirectoryInput struct {
	Keyword string
	Status  string
	Limit   int
}
type userDirectoryAccess struct {
	users  *app.CommandReader[userDirectoryInput, []*iamentity.User]
	groups *app.CommandReader[[]int64, relations.Catalog[*iamentity.Group]]
	roles  *app.CommandReader[[]int64, relations.Catalog[*iamentity.Role]]
}
type userDirectoryCommand = app.Command[userDirectoryInput, *userDirectoryAccess, []*iamentity.User]
type userDirectoryCoverage struct{ TenantID string }

// Directory reads retain their existing tenant-root coverage rule, including System.
type userDirectoryPolicy struct {
	coverage *auth.Fact[userDirectoryCoverage]
}

func (p userDirectoryPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (p userDirectoryPolicy) FactSources() []auth.IFactSource { return []auth.IFactSource{p.coverage} }
func (p userDirectoryPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	if _, err := p.coverage.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	condition := spec.All()
	if !principal.IsSystem {
		condition = svc.DataScopeSpec(ctx)
	}
	return auth.Decision{Allowed: true, Spec: condition}, nil
}

func (s *UserService) compileDirectoryCommands() error {
	if s.userRepo == nil || s.userRepo.Repo == nil || s.groupRepo == nil || s.groupRepo.Repo == nil || s.roleRepo == nil || s.roleRepo.Repo == nil || s.authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "user directory requires its actual user/group/role repositories and IAM declarations")
	}
	coverage, err := auth.NewFact("iam.user.directory_coverage", func(ctx context.Context, _ auth.Request) (userDirectoryCoverage, error) {
		tenantID, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		if s.scopeAuthorizer == nil || iamtenant.CurrentContext(ctx).IsSingle() {
			return userDirectoryCoverage{TenantID: tenantID}, nil
		}
		key, err := svc.RequireTenantMatch(ctx, tenantID)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		tenantCtx, err := svc.BindTenantContext(ctx, key)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		root, err := s.scopeAuthorizer.ResolveTenantScope(tenantCtx, key)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		active, err := s.scopeAuthorizer.ResolveActiveScope(ctx)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		covers, err := s.scopeAuthorizer.ScopeCovers(ctx, active.ID, root.ID)
		if err != nil {
			return userDirectoryCoverage{}, err
		}
		if !covers {
			return userDirectoryCoverage{}, errors.NewCode(errors.Forbidden, "当前授权域不覆盖目标资源")
		}
		return userDirectoryCoverage{TenantID: key}, nil
	})
	if err != nil {
		return err
	}
	s.directoryCommands = map[string]*userDirectoryCommand{}
	for _, action := range []string{"search", "by_status"} {
		resources := []app.CommandResource[userDirectoryInput]{}
		for _, name := range []string{"users", "groups", "roles"} {
			provider, resource := s.directoryProvider(name)
			authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindList, Permission: svc.UserPermissionSet.Code(iamperm.ActionRead)}}}, ResourceAccess: auth.ResourceAccessData,
				Rules: []auth.Rule{{ID: "iam.user.directory", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{userDirectoryPolicy{coverage}}}}},
				auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
			if err != nil {
				return err
			}
			binding := app.CommandResource[userDirectoryInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
				ConditionPath: "CommandReader -> tenant and resource condition before directory filtering/limit; trusted returned user IDs -> independent conditioned group/role association catalogs",
				Intent:        func(userDirectoryInput) (auth.Request, error) { return auth.Request{}, nil }}
			if name != "users" {
				binding.ReuseFactsFrom = "users"
			}
			resources = append(resources, binding)
		}
		command, err := app.NewCommand(app.CommandOptions[userDirectoryInput, *userDirectoryAccess, []*iamentity.User]{Resources: resources,
			Access: func(_ context.Context, in userDirectoryInput, grants []*app.CommandGrant) (*userDirectoryAccess, error) {
				return s.bindDirectoryAccess(action, in, grants)
			},
			Handler: func(ctx context.Context, in userDirectoryInput, access *userDirectoryAccess) ([]*iamentity.User, error) {
				users, err := access.users.Read(ctx, in)
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
				groupByID := map[int64]*iamentity.Group{}
				for _, group := range groups.Items {
					groupByID[group.ID] = group
				}
				for _, link := range groups.Links {
					if group := groupByID[link.TargetID]; group != nil {
						byID[link.SourceID].Groups = append(byID[link.SourceID].Groups, *group)
					}
				}
				roleByID := map[int64]*iamentity.Role{}
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
		if err != nil {
			return err
		}
		s.directoryCommands[action] = command
	}
	return nil
}

func (s *UserService) directoryProvider(name string) (app.IExecutionDescriptorProvider, string) {
	switch name {
	case "groups":
		return s.groupRepo.Repo, svc.GroupResourceKind
	case "roles":
		return s.roleRepo.Repo, svc.RoleResourceKind
	default:
		return s.userRepo.Repo, svc.UserResourceKind
	}
}

func (s *UserService) bindDirectoryAccess(action string, in userDirectoryInput, grants []*app.CommandGrant) (*userDirectoryAccess, error) {
	if len(grants) != 3 {
		return nil, errors.NewCode(errors.InvalidInput, "user directory requires all three grants")
	}
	for i, name := range []string{"users", "groups", "roles"} {
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "user directory grant differs from its declaration")
		}
		_, resource := s.directoryProvider(name)
		request, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if request.Resource != resource || request.Action != action+"_"+name {
			return nil, errors.NewCode(errors.InvalidInput, "user directory action differs from its declaration")
		}
	}
	access := &userDirectoryAccess{}
	known := map[int64]bool{}
	var err error
	access.users, err = app.NewCommandReader(s.userRepo.Repo, grants[0], func(ctx context.Context, requested userDirectoryInput, condition spec.Spec) ([]*iamentity.User, error) {
		if requested != in {
			return nil, errors.NewCode(errors.Forbidden, "user directory query differs from its frozen intent")
		}
		var users []*iamentity.User
		var err error
		if action == "search" {
			users, err = s.userRepo.SearchUsers(ctx, in.Keyword, in.Limit, condition)
		} else {
			users, err = s.userRepo.FindByStatus(ctx, in.Status, condition)
		}
		if err != nil {
			return nil, err
		}
		for _, user := range users {
			if user == nil || user.ID <= 0 {
				return nil, errors.NewCode(errors.Forbidden, "user directory returned an invalid identity")
			}
			known[user.ID] = true
		}
		return users, nil
	})
	if err != nil {
		return nil, err
	}
	access.groups, err = app.NewCommandReader(s.groupRepo.Repo, grants[1], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
		for _, id := range ids {
			if !known[id] {
				return relations.Catalog[*iamentity.Group]{}, errors.NewCode(errors.Forbidden, "group source is outside the trusted user directory")
			}
		}
		return s.groupRepo.GroupsForUsers(ctx, ids, condition)
	})
	if err != nil {
		return nil, err
	}
	access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[2], func(ctx context.Context, ids []int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
		for _, id := range ids {
			if !known[id] {
				return relations.Catalog[*iamentity.Role]{}, errors.NewCode(errors.Forbidden, "role source is outside the trusted user directory")
			}
		}
		return s.roleRepo.RolesForUsers(ctx, ids, condition)
	})
	return access, err
}

func (s *UserService) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if command := s.directoryCommands[action]; command != nil {
		return command.AuthorizationBinding()
	}
	if command := s.associationReads[action]; command != nil {
		return command.AuthorizationBinding()
	}
	if command := s.statusCommands[action]; command != nil {
		return command.AuthorizationBinding()
	}
	return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user action is not declared")
}
