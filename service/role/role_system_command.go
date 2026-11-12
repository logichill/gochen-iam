package role

import (
	"context"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
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

const roleNamespaceResource = "iam.role.namespace"

type roleSystemPolicy struct {
	coverage *auth.Fact[roleReadCoverage]
	http     bool
}

func (p roleSystemPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p roleSystemPolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.coverage}
}
func (p roleSystemPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	if _, err := hostauthz.RequirePrincipal(ctx); err != nil {
		return auth.Decision{}, err
	}
	if p.http {
		if _, err := (roleHTTPEntryPolicy{}).Evaluate(ctx, req); err != nil {
			return auth.Decision{}, err
		}
	}
	if _, err := p.coverage.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	// The system directory retains its tenant-wide projection after root coverage.
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

type roleSystemAccess struct {
	roles      *app.CommandReader[struct{}, []*iamentity.Role]
	namespaces *app.CommandReader[[]int64, []*iamentity.Scope]
}
type roleSystemCommand = app.Command[struct{}, *roleSystemAccess, []*iamentity.Role]

func (s *RoleService) compileSystemCommands() error {
	namespaces, err := ormrepo.NewRepo[*iamentity.Scope, int64](s.roleRepo.Orm(), "scopes",
		ormrepo.WithResourceKind[*iamentity.Scope, int64](roleNamespaceResource),
		ormrepo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""))
	if err != nil {
		return err
	}
	coverage, err := auth.NewFact("iam.role.system_coverage", func(ctx context.Context, _ auth.Request) (roleReadCoverage, error) {
		key, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return roleReadCoverage{}, err
		}
		if err := svc.RequirePermissionInTenant(ctx, s.scopeAuthorizer, svc.RolePermissionSet.Code(iamperm.ActionRead), key); err != nil {
			return roleReadCoverage{}, err
		}
		return roleReadCoverage{TenantID: key}, nil
	})
	if err != nil {
		return err
	}
	s.systemCommands = map[string]*roleSystemCommand{}
	for _, action := range []string{"system_roles", "http_system_roles"} {
		resources := make([]app.CommandResource[struct{}], 0, 2)
		for i, name := range []string{"roles", "namespaces"} {
			var provider app.IExecutionDescriptorProvider = s.roleRepo.Repo
			resource, operation := svc.RoleResourceKind, action
			if i == 1 {
				provider, resource, operation = namespaces, roleNamespaceResource, action+"_namespace"
			}
			authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource,
				Actions: []auth.Action{{Name: operation, Kind: auth.KindList, Permission: svc.RolePermissionSet.Code(iamperm.ActionRead)}}},
				ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.role.system_directory", System: auth.SystemCheckConstraints,
					Constraints: []auth.IPolicy{roleSystemPolicy{coverage: coverage, http: action == "http_system_roles"}}}}},
				auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
			if err != nil {
				return err
			}
			binding := app.CommandResource[struct{}]{Name: name, Repository: provider, Authorizer: authorizer, Action: operation,
				ConditionPath: "CommandReader -> tenant system-role directory; independent namespace condition before trusted NamespaceScopeID batches; no user/group preload",
				Intent:        func(struct{}) (auth.Request, error) { return auth.Request{}, nil }}
			if i == 1 {
				binding.ReuseFactsFrom = "roles"
			}
			resources = append(resources, binding)
		}
		command, err := app.NewCommand(app.CommandOptions[struct{}, *roleSystemAccess, []*iamentity.Role]{Resources: resources,
			Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (*roleSystemAccess, error) {
				return s.bindSystemAccess(action, namespaces, grants)
			}, Handler: func(ctx context.Context, _ struct{}, access *roleSystemAccess) ([]*iamentity.Role, error) {
				roles, err := access.roles.Read(ctx, struct{}{})
				if err != nil {
					return nil, err
				}
				ids := make([]int64, 0, len(roles))
				for _, role := range roles {
					if role.NamespaceScopeID > 0 {
						ids = append(ids, role.NamespaceScopeID)
					}
				}
				scopes, err := access.namespaces.Read(ctx, ids)
				if err != nil {
					return nil, err
				}
				byID := make(map[int64]*iamentity.Scope, len(scopes))
				for _, scope := range scopes {
					byID[scope.ID] = scope
				}
				for _, role := range roles {
					role.NamespaceScope = byID[role.NamespaceScopeID]
				}
				return roles, nil
			}})
		if err != nil {
			return err
		}
		s.systemCommands[action] = command
	}
	return nil
}

func (s *RoleService) bindSystemAccess(action string, namespaces *ormrepo.Repo[*iamentity.Scope, int64], grants []*app.CommandGrant) (*roleSystemAccess, error) {
	if len(grants) != 2 {
		return nil, errors.NewCode(errors.InvalidInput, "system role directory requires both grants")
	}
	for i, name := range []string{"roles", "namespaces"} {
		resource, operation := svc.RoleResourceKind, action
		if i == 1 {
			resource, operation = roleNamespaceResource, action+"_namespace"
		}
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "system role grant differs from its declaration")
		}
		request, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if request.Resource != resource || request.Action != operation || len(request.IDs) != 0 || len(request.Targets) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "system role request differs from its declaration")
		}
	}
	known := map[int64]bool{}
	access := &roleSystemAccess{}
	var err error
	access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[0], func(ctx context.Context, _ struct{}, condition spec.Spec) ([]*iamentity.Role, error) {
		key, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return nil, err
		}
		condition = spec.And(condition, spec.Eq(meta.ByField("TenantID"), key), spec.Eq(meta.ByField("IsSystem"), true))
		roles := []*iamentity.Role{}
		for offset := 0; ; offset += 1000 {
			items, err := s.roleRepo.Repo.Query(ctx, query.QueryOptions{Limit: 1000, Offset: offset,
				Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}}, condition)
			if err != nil {
				return nil, err
			}
			for _, role := range items {
				if role == nil || role.ID <= 0 || role.TenantID != key {
					return nil, errors.NewCode(errors.Forbidden, "system role directory returned an invalid identity")
				}
				if role.NamespaceScopeID > 0 {
					known[role.NamespaceScopeID] = true
				}
			}
			roles = append(roles, items...)
			if len(items) < 1000 {
				break
			}
		}
		return roles, nil
	})
	if err != nil {
		return nil, err
	}
	access.namespaces, err = app.NewCommandReader(namespaces, grants[1], func(ctx context.Context, ids []int64, condition spec.Spec) ([]*iamentity.Scope, error) {
		unique := []any{}
		seen := map[int64]bool{}
		for _, id := range ids {
			if !known[id] {
				return nil, errors.NewCode(errors.Forbidden, "namespace differs from the trusted system role directory")
			}
			if !seen[id] {
				unique = append(unique, id)
				seen[id] = true
			}
		}
		scopes := []*iamentity.Scope{}
		for start := 0; start < len(unique); start += 1000 {
			items, err := namespaces.Query(ctx, query.QueryOptions{Limit: 1000}, spec.And(condition, spec.In(meta.ID(), unique[start:min(start+1000, len(unique))]...)))
			if err != nil {
				return nil, err
			}
			scopes = append(scopes, items...)
		}
		return scopes, nil
	})
	return access, err
}

func (s *RoleService) SystemRolesHTTP(ctx context.Context) ([]*iamentity.Role, error) {
	return s.systemCommands["http_system_roles"].Execute(ctx, struct{}{})
}

func (s *RoleService) SystemAuthorizationBinding() (auth.EntryBinding, error) {
	if s == nil || s.systemCommands["http_system_roles"] == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "system role directory requires its constructed command")
	}
	return s.systemCommands["http_system_roles"].AuthorizationBinding()
}
