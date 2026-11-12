package scope

import (
	"context"
	"strings"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	"gochen/app"
	"gochen/domain/spec"
	"gochen/errors"
)

type scopeTreeInput struct {
	Operation string
	ID        int64
	Key       string
	Scope     *iamentity.Scope
}
type scopeTreeResult struct {
	Scope *iamentity.Scope
	Items []*iamentity.Scope
	Count int64
}
type tenantReferenceInput struct {
	ID    int64
	Count bool
}
type tenantReferenceResult struct {
	Tenant *iamentity.Tenant
	Count  int64
}
type userReferenceInput struct {
	ID   int64
	Home bool
}
type scopeAccess struct {
	tree           *app.CommandReader[scopeTreeInput, scopeTreeResult]
	writer         *app.CommandWriter[scopeTreeInput, *iamentity.Scope]
	visibilityRead *app.CommandReader[int64, []int64]
	visibility     *app.CommandWriter[struct{}, struct{}]
	tenants        *app.CommandReader[tenantReferenceInput, tenantReferenceResult]
	roles          *app.CommandReader[int64, int64]
	users          *app.CommandReader[userReferenceInput, int64]
	bindings       *app.CommandReader[int64, int64]
	groups         *app.CommandReader[int64, int64]
	guards         []*app.CommandReader[struct{}, struct{}]
}

func requireScopeCatalog(condition spec.Spec) error {
	if !condition.IsAll() {
		return errors.NewCode(errors.Forbidden, "scope governance requires the complete authorized catalog")
	}
	return nil
}

// bindAccess selects only the service's actual providers and keeps all native calls
// behind grant identity, action, condition and lifetime checks.
func (s *ScopeService) bindAccess(in scopeCommandInput, names []string, grants []*app.CommandGrant) (*scopeAccess, error) {
	if len(names) != len(grants) {
		return nil, errors.NewCode(errors.InvalidInput, "scope capabilities require all declared resource grants")
	}
	access := &scopeAccess{}
	base := strings.TrimPrefix(in.Action, "http_")
	read := base == "governance" || base == "list" || base == "visibility"
	for i, name := range names {
		provider := app.IExecutionDescriptorProvider(s.scopeRepo)
		if name != "tree" {
			provider = s.catalogs[name]
		}
		grant := grants[i]
		if grant == nil || grant.Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "scope capability action differs from the declared command")
		}
		request, err := grant.Request()
		if err != nil {
			return nil, err
		}
		if request.Action != in.Action || request.Resource != "iam.scope."+name {
			return nil, errors.NewCode(errors.InvalidInput, "scope capability action differs from the declared command")
		}
		guard, err := app.NewCommandReader(provider, grant, func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
			return struct{}{}, requireScopeCatalog(condition)
		})
		if err != nil {
			return nil, err
		}
		access.guards = append(access.guards, guard)
		switch name {
		case "tree":
			access.tree, err = app.NewCommandReader(provider, grant, func(ctx context.Context, input scopeTreeInput, condition spec.Spec) (scopeTreeResult, error) {
				var out scopeTreeResult
				if err := requireScopeCatalog(condition); err != nil {
					return out, err
				}
				var err error
				switch input.Operation {
				case "get":
					out.Scope, err = s.scopeRepo.Get(ctx, input.ID)
				case "key":
					out.Scope, err = s.scopeRepo.FindByKey(ctx, input.Key)
				case "list":
					out.Items, err = s.scopeRepo.List(ctx)
				case "children":
					out.Count, err = s.scopeRepo.CountChildren(ctx, input.ID)
				default:
					err = errors.NewCode(errors.InvalidInput, "unknown scope read operation")
				}
				if err == nil && input.Operation == "get" && (out.Scope == nil || out.Scope.ID != input.ID) {
					return scopeTreeResult{}, errors.NewCode(errors.Forbidden, "scope result differs from its requested ID")
				}
				return out, err
			})
			if err == nil && !read {
				access.writer, err = app.NewCommandWriter(provider, grant, func(ctx context.Context, input scopeTreeInput, condition spec.Spec) (*iamentity.Scope, error) {
					if err := requireScopeCatalog(condition); err != nil {
						return nil, err
					}
					if input.Scope == nil {
						return nil, errors.NewCode(errors.InvalidInput, "scope write requires an entity")
					}
					expected := "update"
					if base == "create" || base == "delete" {
						expected = base
					}
					if input.Operation != expected || base != "create" && input.Scope.ID != in.ID || base == "create" && input.Scope.ID != 0 {
						return nil, errors.NewCode(errors.InvalidInput, "scope write differs from its declared action or target")
					}
					var err error
					switch input.Operation {
					case "create":
						err = s.scopeRepo.Create(ctx, input.Scope, condition)
					case "update":
						err = s.scopeRepo.Update(ctx, input.Scope, condition)
					case "delete":
						err = s.scopeRepo.Delete(ctx, input.Scope, condition)
					default:
						err = errors.NewCode(errors.InvalidInput, "unknown scope write operation")
					}
					return input.Scope, err
				})
			}
		case "visibility":
			if read {
				access.visibilityRead, err = app.NewCommandReader(provider, grant, func(ctx context.Context, id int64, condition spec.Spec) ([]int64, error) {
					if err := requireScopeCatalog(condition); err != nil {
						return nil, err
					}
					if id != in.ID {
						return nil, errors.NewCode(errors.InvalidInput, "scope visibility target differs from the frozen request")
					}
					return s.scopeRepo.VisibleScopeIDs(ctx, id)
				})
			} else {
				access.visibility, err = app.NewCommandWriter(provider, grant, func(ctx context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
					if err := requireScopeCatalog(condition); err != nil {
						return struct{}{}, err
					}
					return struct{}{}, s.scopeRepo.RebuildVisibilityMap(ctx)
				})
			}
		case "tenants":
			actual := s.catalogs[name].owner.(*tenantrepo.TenantRepo)
			access.tenants, err = app.NewCommandReader(provider, grant, func(ctx context.Context, input tenantReferenceInput, condition spec.Spec) (tenantReferenceResult, error) {
				if err := requireScopeCatalog(condition); err != nil {
					return tenantReferenceResult{}, err
				}
				if input.Count {
					count, err := actual.CountByRootScopeID(ctx, input.ID)
					return tenantReferenceResult{Count: count}, err
				}
				value, err := actual.FindByRootScopeID(ctx, input.ID)
				if err == nil && (value == nil || value.RootScopeID == nil || *value.RootScopeID != input.ID) {
					return tenantReferenceResult{}, errors.NewCode(errors.Forbidden, "tenant reference differs from its scope ID")
				}
				return tenantReferenceResult{Tenant: value}, err
			})
		case "roles":
			access.roles, err = bindScopeCount(provider, grant, s.catalogs[name].owner.(*rolerepo.RoleRepo).CountByNamespaceScopeID)
		case "users":
			actual := s.catalogs[name].owner.(*userrepo.UserRepo)
			access.users, err = app.NewCommandReader(provider, grant, func(ctx context.Context, input userReferenceInput, condition spec.Spec) (int64, error) {
				if err := requireScopeCatalog(condition); err != nil {
					return 0, err
				}
				if input.Home {
					return actual.CountByHomeScopeID(ctx, input.ID)
				}
				return actual.CountByManagedScopeID(ctx, input.ID)
			})
		case "bindings":
			access.bindings, err = bindScopeCount(provider, grant, s.catalogs[name].owner.(*userrepo.UserRepo).CountRoleBindingsByGrantScopeID)
		case "groups":
			access.groups, err = bindScopeCount(provider, grant, s.catalogs[name].owner.(*grouprepo.GroupRepo).CountByManagedScopeID)
		}
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func bindScopeCount(provider app.IExecutionDescriptorProvider, grant *app.CommandGrant, count func(context.Context, int64) (int64, error)) (*app.CommandReader[int64, int64], error) {
	return app.NewCommandReader(provider, grant, func(ctx context.Context, id int64, condition spec.Spec) (int64, error) {
		if err := requireScopeCatalog(condition); err != nil {
			return 0, err
		}
		return count(ctx, id)
	})
}
func (a *scopeAccess) check(ctx context.Context) error {
	for _, guard := range a.guards {
		if _, err := guard.Read(ctx, struct{}{}); err != nil {
			return err
		}
	}
	return nil
}
func (a *scopeAccess) get(ctx context.Context, id int64) (*iamentity.Scope, error) {
	out, err := a.tree.Read(ctx, scopeTreeInput{Operation: "get", ID: id})
	return out.Scope, err
}
func (a *scopeAccess) findKey(ctx context.Context, key string) (*iamentity.Scope, error) {
	out, err := a.tree.Read(ctx, scopeTreeInput{Operation: "key", Key: key})
	return out.Scope, err
}
func (a *scopeAccess) list(ctx context.Context) ([]*iamentity.Scope, error) {
	out, err := a.tree.Read(ctx, scopeTreeInput{Operation: "list"})
	return out.Items, err
}
func (a *scopeAccess) children(ctx context.Context, id int64) (int64, error) {
	out, err := a.tree.Read(ctx, scopeTreeInput{Operation: "children", ID: id})
	return out.Count, err
}
func (a *scopeAccess) save(ctx context.Context, operation string, scope *iamentity.Scope) (*iamentity.Scope, error) {
	return a.writer.Write(ctx, scopeTreeInput{Operation: operation, Scope: scope})
}
func (a *scopeAccess) rebuild(ctx context.Context) error {
	_, err := a.visibility.Write(ctx, struct{}{})
	return err
}
func (a *scopeAccess) findTenant(ctx context.Context, id int64) (*iamentity.Tenant, error) {
	out, err := a.tenants.Read(ctx, tenantReferenceInput{ID: id})
	return out.Tenant, err
}
func (a *scopeAccess) countTenant(ctx context.Context, id int64) (int64, error) {
	out, err := a.tenants.Read(ctx, tenantReferenceInput{ID: id, Count: true})
	return out.Count, err
}
