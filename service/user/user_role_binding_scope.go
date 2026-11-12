package user

import (
	"context"

	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

// Binding scope reads are derived from an authorized user and its real binding.
// The native coverage operation consumes the complete visibility projection.
type userBindingScopeAccess struct {
	guard           *app.CommandReader[struct{}, struct{}]
	visibilityGuard *app.CommandReader[struct{}, struct{}]
	visibility      *app.CommandReader[userrepo.BindingRecord, struct{}]
	root            *svc.TenantScopeReader
}

func bindingScopeResources[Input any](scopes *svc.ScopeAuthorizer, action, permission string, guards []auth.IPolicy) ([]app.CommandResource[Input], error) {
	tenants, provider, err := scopes.TenantScopeProviders()
	if err != nil {
		return nil, err
	}
	var resources []app.CommandResource[Input]
	for _, name := range []string{"scope", "visibility", "tenant", "root"} {
		actual := provider
		if name == "tenant" {
			actual = tenants
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.binding_scope." + name,
			Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindRead, Permission: permission}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "iam.user.binding_scope." + name, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: actual.ExecutionDescriptor().Metadata()})
		if err != nil {
			return nil, err
		}
		resource := app.CommandResource[Input]{Name: name, Repository: actual, Authorizer: authorizer, Action: action + "_" + name,
			ConditionPath: "CommandReader -> trusted binding association -> complete visibility predicate and actual scope/root condition -> existing grant visibility and ancestor projection",
			Intent:        func(Input) (auth.Request, error) { return auth.Request{}, nil }}
		if name == "tenant" || name == "root" {
			resource.When = func(ctx context.Context, _ Input, _ []*app.CommandGrant) (bool, error) {
				return tenant.CurrentContext(ctx).IsSingle(), nil
			}
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (s *UserService) bindBindingScopes(ctx context.Context, action string, grants []*app.CommandGrant, known func(userrepo.BindingRecord) bool) (*userBindingScopeAccess, error) {
	if len(grants) != 4 || known == nil || s.scopeAuthorizer == nil {
		return nil, errors.NewCode(errors.InvalidInput, "binding scope requires all declared actual resources")
	}
	for i, name := range []string{"scope", "visibility", "tenant", "root"} {
		if (name == "tenant" || name == "root") && !tenant.CurrentContext(ctx).IsSingle() {
			if grants[i] != nil {
				return nil, errors.NewCode(errors.InvalidInput, "tenant root capability is outside the binding branch")
			}
			continue
		}
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "binding scope capability differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if req.Resource != "iam.user.binding_scope."+name || req.Action != action+"_"+name || len(req.IDs) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "binding scope capability differs from its action or target")
		}
	}
	_, provider, err := s.scopeAuthorizer.TenantScopeProviders()
	if err != nil {
		return nil, err
	}
	a := &userBindingScopeAccess{}
	a.guard, err = app.NewCommandReader(provider, grants[0], func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
		return struct{}{}, requireRoleAssignmentCatalog(condition)
	})
	if err != nil {
		return nil, err
	}
	a.visibilityGuard, err = app.NewCommandReader(provider, grants[1], func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
		return struct{}{}, requireRoleAssignmentCatalog(condition)
	})
	if err != nil {
		return nil, err
	}
	if tenant.CurrentContext(ctx).IsSingle() {
		a.root, err = s.scopeAuthorizer.BindTenantScopeReader(grants[2], grants[3])
		if err != nil {
			return nil, err
		}
	}
	a.visibility, err = app.NewCommandReader(provider, grants[1], func(ctx context.Context, binding userrepo.BindingRecord, condition spec.Spec) (struct{}, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return struct{}{}, err
		}
		if !known(binding) {
			return struct{}{}, errors.NewCode(errors.Forbidden, "scope lookup differs from the trusted binding")
		}
		if binding.GrantScopeID <= 0 {
			return struct{}{}, nil
		}
		if a.root != nil {
			root, err := a.root.Read(ctx)
			if err != nil {
				return struct{}{}, err
			}
			allowed, err := s.scopeAuthorizer.ScopeCovers(ctx, binding.GrantScopeID, root.ID)
			if err != nil {
				return struct{}{}, err
			}
			if !allowed {
				return struct{}{}, errors.NewCode(errors.Forbidden, "目标授权域不覆盖 single tenant root scope")
			}
		} else if activeID := svc.ManagedScopeIDFromContext(ctx); activeID > 0 && activeID != binding.GrantScopeID {
			allowed, err := s.scopeAuthorizer.ScopeCovers(ctx, activeID, binding.GrantScopeID)
			if err != nil {
				return struct{}{}, err
			}
			if !allowed {
				return struct{}{}, errors.NewCode(errors.Forbidden, "当前 active scope 无法查看目标授权域绑定")
			}
		}
		return struct{}{}, nil
	})
	return a, err
}

func (a *userBindingScopeAccess) check(ctx context.Context, binding userrepo.BindingRecord) error {
	if err := a.preflight(ctx); err != nil {
		return err
	}
	_, err := a.visibility.Read(ctx, binding)
	return err
}

func (a *userBindingScopeAccess) preflight(ctx context.Context) error {
	if _, err := a.guard.Read(ctx, struct{}{}); err != nil {
		return err
	}
	_, err := a.visibilityGuard.Read(ctx, struct{}{})
	return err
}
