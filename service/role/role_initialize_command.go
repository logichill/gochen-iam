package role

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
)

type roleInitializationPolicy struct{ service *RoleService }

func (roleInitializationPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p roleInitializationPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	tenant, err := svc.TenantIDFromContext(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	if err := svc.RequirePermissionInTenant(ctx, p.service.scopeAuthorizer, "role:api:write", tenant); err != nil {
		return auth.Decision{}, err
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

type roleInitializeAccess struct {
	roles *app.CommandRepository[*iamentity.Role, int64]
	names *app.CommandReader[string, bool]
	root  *svc.TenantScopeReader
}
type roleInitializeCommand = app.Command[struct{}, *roleInitializeAccess, struct{}]

func (s *RoleService) compileInitializeCommand() error {
	descriptor := auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "initialize", Kind: auth.KindCreate, Permission: "role:api:write"}}}
	authorizer, err := s.authorizer.Compile(descriptor, s.roleRepo.ExecutionDescriptor().Metadata(), roleInitializationPolicy{service: s})
	if err != nil {
		return err
	}
	resources := []app.CommandResource[struct{}]{{Name: "roles", Repository: s.roleRepo, Authorizer: authorizer, Action: "initialize", ConditionPath: "CommandRepository.Create -> tenant-bound builtin role under complete create decision", Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil }}}
	providers := []struct {
		name string
		repo app.IExecutionDescriptorProvider
	}{{"names", s.roleRepo.Repo}}
	if s.scopeAuthorizer != nil {
		tenants, scopes, err := s.scopeAuthorizer.TenantScopeProviders()
		if err != nil {
			return err
		}
		providers = append(providers, struct {
			name string
			repo app.IExecutionDescriptorProvider
		}{"tenant", tenants}, struct {
			name string
			repo app.IExecutionDescriptorProvider
		}{"root", scopes})
	}
	for _, provider := range providers {
		d := auth.Descriptor{Resource: "iam.role.initialize_" + provider.name, Actions: []auth.Action{{Name: "initialize_" + provider.name, Kind: auth.KindRead, Permission: "role:api:write"}}}
		a, err := auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: d.Resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.repo.ExecutionDescriptor().Metadata()})
		if err != nil {
			return err
		}
		resources = append(resources, app.CommandResource[struct{}]{Name: provider.name, Repository: provider.repo, Authorizer: a, Action: "initialize_" + provider.name, ConditionPath: "CommandReader -> complete tenant name invariant or trusted Tenant.RootScopeID relation", Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil }})
	}
	s.initializeCommand, err = app.NewCommand(app.CommandOptions[struct{}, *roleInitializeAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (*roleInitializeAccess, error) {
			a := &roleInitializeAccess{}
			var err error
			a.roles, err = app.NewCommandRepository(s.roleRepo, grants[0])
			if err != nil {
				return nil, err
			}
			a.names, err = app.NewCommandReader(s.roleRepo.Repo, grants[1], func(ctx context.Context, name string, condition spec.Spec) (bool, error) {
				tenant, err := svc.TenantIDFromContext(ctx)
				if err != nil {
					return false, err
				}
				items, err := s.roleRepo.Repo.Query(ctx, query.QueryOptions{Limit: 1}, spec.And(condition, spec.Eq(meta.ByField("TenantID"), tenant), spec.Eq(meta.ByField("Name"), name)))
				return len(items) > 0, err
			})
			if err != nil {
				return nil, err
			}
			if s.scopeAuthorizer != nil {
				a.root, err = s.scopeAuthorizer.BindTenantScopeReader(grants[2], grants[3])
			}
			return a, err
		}, Handler: func(ctx context.Context, _ struct{}, a *roleInitializeAccess) (struct{}, error) {
			err := s.roleRepo.WithinTx(ctx, func(txCtx context.Context) error {
				tenant, err := svc.TenantIDFromContext(txCtx)
				if err != nil {
					return err
				}
				scopeID := svc.ManagedScopeIDFromContext(txCtx)
				builtins := []*iamentity.Role{iamentity.SystemAdminRole, iamentity.UserRole}
				if a.root != nil {
					root, err := a.root.Read(txCtx)
					if err != nil {
						return err
					}
					scopeID = root.ID
					if root.Type != iamentity.ScopeTypePlatform {
						builtins = []*iamentity.Role{iamentity.TenantAdminRole, iamentity.UserRole}
					}
				}
				for _, builtin := range builtins {
					exists, err := a.names.Read(txCtx, builtin.Name)
					if err != nil {
						return err
					}
					if exists {
						continue
					}
					item, err := meta.Clone(builtin)
					if err != nil {
						return err
					}
					item.TenantID, item.OwnerID, item.NamespaceScopeID = tenant, svc.TenantOwnerID(tenant), scopeID
					item.Code = builtin.Name
					if err := a.roles.Create(txCtx, item); err != nil {
						return err
					}
				}
				return nil
			})
			return struct{}{}, err
		}})
	return err
}
