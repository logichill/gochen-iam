package tenant

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type TenantCommandInput struct {
	ID     int64
	Create *svc.CreateTenantRequest
	Update *svc.UpdateTenantRequest
}

type TenantCommandResult struct {
	Tenant  *iamentity.Tenant
	Tenants []*iamentity.Tenant
	Scope   *iamentity.Scope
}

type tenantCommandInput struct {
	TenantCommandInput
	Action string
}

type tenantCommand = app.Command[tenantCommandInput, *tenantAccess, TenantCommandResult]

type tenantRootCatalogItem struct {
	ID string `entity:"id"`
}
type tenantRootCatalog struct {
	execution app.ExecutionDescriptor
	owner     app.IExecutionDescriptorProvider
}

func (p *tenantRootCatalog) ExecutionDescriptor() app.ExecutionDescriptor { return p.execution }

type tenantAccess struct {
	tenant  *app.CommandRepository[*iamentity.Tenant, int64]
	list    *app.CommandReader[struct{}, []*iamentity.Tenant]
	names   *app.CommandReader[string, bool]
	root    *app.CommandWriter[*iamentity.Tenant, *iamentity.Scope]
	guards  []*app.CommandReader[struct{}, struct{}]
	trusted map[int64]iamentity.Tenant
}

func (a *tenantAccess) remember(tenant *iamentity.Tenant) error {
	if tenant == nil {
		return errors.NewCode(errors.InvalidInput, "trusted tenant is required")
	}
	frozen, err := meta.Clone(*tenant)
	if err != nil {
		return err
	}
	a.trusted[tenant.ID] = frozen
	return nil
}

type tenantHTTPPolicy struct{}

func (tenantHTTPPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (tenantHTTPPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	id, err := strconv.ParseInt(principal.SubjectID, 10, 64)
	if err != nil || id <= 0 {
		return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	if !iamtenant.CurrentContext(ctx).IsSingle() && iamauth.ActiveScopeKindFromContext(ctx) != iamentity.ScopeTypePlatform {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不是 platform")
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *TenantService) compileCommands() error {
	if s.tenantRepo == nil || s.tenantRepo.Repo == nil || s.scopeAuthorizer == nil || s.authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "tenant service requires actual tenant/scope repositories and IAM declarations")
	}
	tenants, scopes, err := s.scopeAuthorizer.TenantScopeProviders()
	if err != nil {
		return err
	}
	if tenants != s.tenantRepo.Repo {
		return errors.NewCode(errors.InvalidInput, "tenant provisioning must use the service's actual tenant repository")
	}
	metadata, err := meta.Describe[*tenantRootCatalogItem]()
	if err != nil {
		return err
	}
	execution, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		return err
	}
	s.rootProvider = &tenantRootCatalog{execution: execution, owner: scopes}
	s.commands = map[string]*tenantCommand{}
	for _, action := range []string{"create", "update", "activate", "deactivate", "repair", "read", "list", "http_activate", "http_deactivate", "http_repair"} {
		base := strings.TrimPrefix(action, "http_")
		permission, kind := svc.TenantPermissionSet.Code(iamperm.ActionWrite), auth.KindUpdate
		if base == "create" {
			kind = auth.KindCreate
		}
		if base == "read" || base == "list" {
			permission = svc.TenantPermissionSet.Code(iamperm.ActionRead)
			kind = auth.KindRead
		}
		if base == "list" {
			kind = auth.KindList
		}
		if base == "activate" || base == "deactivate" {
			permission = svc.TenantPermissionSet.Code(iamperm.ActionActivate)
		}
		names := []string{"tenant"}
		if base == "create" {
			names = append(names, "names")
		}
		if base == "create" || base == "repair" {
			names = append(names, "root", "visibility", "link")
		}
		var policies []auth.IPolicy
		if strings.HasPrefix(action, "http_") {
			policies = []auth.IPolicy{tenantHTTPPolicy{}}
		}
		resources := []app.CommandResource[tenantCommandInput]{}
		for _, name := range names {
			provider := app.IExecutionDescriptorProvider(s.tenantRepo)
			resourceKind, resource := kind, svc.TenantResourceKind
			if name == "names" {
				resourceKind = auth.KindRead
			}
			if name == "root" {
				provider = scopes
				resource = svc.ScopeResourceKind
				resourceKind = auth.KindUpdate
			}
			if name == "visibility" {
				provider = s.rootProvider
				resource = svc.ScopeResourceKind
				resourceKind = auth.KindUpdate
			}
			if name == "link" {
				resourceKind = auth.KindUpdate
			}
			authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action, Kind: resourceKind, Permission: permission}}}, provider.ExecutionDescriptor().Metadata(), policies...)
			if err != nil {
				return err
			}
			primary := name == "tenant"
			resources = append(resources, app.CommandResource[tenantCommandInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action,
				ConditionPath: "CommandRepository/Reader -> explicit tenant Spec; bound root provisioner -> complete scope/visibility/link capabilities -> native atomic root repair and tenant version protection",
				Intent: func(in tenantCommandInput) (auth.Request, error) {
					if in.Action != action {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "tenant action differs from declaration")
					}
					if primary && base != "create" && base != "list" {
						if in.ID <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "tenant ID must be positive")
						}
						return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
					}
					return auth.Request{}, nil
				}})
		}
		command, err := app.NewCommand(app.CommandOptions[tenantCommandInput, *tenantAccess, TenantCommandResult]{Resources: resources,
			Access: func(_ context.Context, in tenantCommandInput, grants []*app.CommandGrant) (*tenantAccess, error) {
				return s.bindAccess(in, names, grants, scopes)
			},
			Handler: func(ctx context.Context, in tenantCommandInput, access *tenantAccess) (TenantCommandResult, error) {
				for _, guard := range access.guards {
					if _, err := guard.Read(ctx, struct{}{}); err != nil {
						return TenantCommandResult{}, err
					}
				}
				return s.handleCommand(ctx, in, access)
			}})
		if err != nil {
			return err
		}
		s.commands[action] = command
	}
	return nil
}

func (s *TenantService) bindAccess(in tenantCommandInput, names []string, grants []*app.CommandGrant, scopes app.IExecutionDescriptorProvider) (*tenantAccess, error) {
	access := &tenantAccess{trusted: map[int64]iamentity.Tenant{}}
	if len(names) != len(grants) {
		return nil, errors.NewCode(errors.InvalidInput, "tenant command requires every declared resource")
	}
	for i, name := range names {
		grant := grants[i]
		if grant == nil || grant.Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "tenant resource differs from declaration")
		}
		request, err := grant.Request()
		if err != nil {
			return nil, err
		}
		expected := svc.TenantResourceKind
		if name == "root" || name == "visibility" {
			expected = svc.ScopeResourceKind
		}
		if request.Action != in.Action || request.Resource != expected {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability action or resource differs from its declaration")
		}
		switch name {
		case "tenant":
			access.tenant, err = app.NewCommandRepository(s.tenantRepo, grant)
			if err == nil && in.Action == "list" {
				access.list, err = app.NewCommandReader(s.tenantRepo, grant, func(ctx context.Context, _ struct{}, condition spec.Spec) ([]*iamentity.Tenant, error) {
					var result []*iamentity.Tenant
					for offset := 0; ; offset += 1000 {
						items, err := s.tenantRepo.Query(ctx, query.QueryOptions{Offset: offset, Limit: 1000, Sorts: []query.Sort{{Field: "id", Direction: query.ASC}}}, condition)
						if err != nil {
							return nil, err
						}
						result = append(result, items...)
						if len(items) < 1000 {
							return result, nil
						}
					}
				})
			}
		case "names":
			access.names, err = app.NewCommandReader(s.tenantRepo, grant, func(ctx context.Context, key string, condition spec.Spec) (bool, error) {
				count, err := s.tenantRepo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("Key"), key)))
				return count > 0, err
			})
		case "root", "visibility", "link":
			provider := app.IExecutionDescriptorProvider(s.tenantRepo)
			if name == "root" {
				provider = scopes
			}
			if name == "visibility" {
				provider = s.rootProvider
			}
			guard, bindErr := app.NewCommandReader(provider, grant, func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
				if !condition.IsAll() {
					return struct{}{}, errors.NewCode(errors.Forbidden, "tenant root provisioning requires the complete authorized catalog")
				}
				return struct{}{}, nil
			})
			if bindErr != nil {
				return nil, bindErr
			}
			access.guards = append(access.guards, guard)
			if name == "root" {
				access.root, err = app.NewCommandWriter(scopes, grant, func(ctx context.Context, tenant *iamentity.Tenant, _ spec.Spec) (*iamentity.Scope, error) {
					if tenant == nil {
						return nil, errors.NewCode(errors.InvalidInput, "tenant root requires its trusted tenant")
					}
					trusted, known := access.trusted[tenant.ID]
					rootMatches := tenant.RootScopeID == nil && trusted.RootScopeID == nil || tenant.RootScopeID != nil && trusted.RootScopeID != nil && *tenant.RootScopeID == *trusted.RootScopeID
					if !known || tenant.Key != trusted.Key || tenant.Name != trusted.Name || tenant.Description != trusted.Description || tenant.Status != trusted.Status || !rootMatches || tenant.Version != trusted.Version {
						return nil, errors.NewCode(errors.Forbidden, "tenant root differs from the trusted command target")
					}
					for _, guard := range access.guards {
						if _, err := guard.Read(ctx, struct{}{}); err != nil {
							return nil, err
						}
					}
					return s.scopeAuthorizer.EnsureTenantRootScope(ctx, tenant)
				})
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func (s *TenantService) handleCommand(ctx context.Context, in tenantCommandInput, access *tenantAccess) (TenantCommandResult, error) {
	var out TenantCommandResult
	var err error
	base := strings.TrimPrefix(in.Action, "http_")
	switch base {
	case "create":
		out.Tenant, err = s.createTenant(ctx, in.Create, access)
	case "update":
		out.Tenant, err = s.updateTenant(ctx, in.ID, in.Update, access)
	case "read":
		out.Tenant, err = access.tenant.Get(ctx, in.ID)
	case "list":
		out.Tenants, err = access.list.Read(ctx, struct{}{})
	case "activate", "deactivate", "repair":
		err = s.tenantRepo.WithinTx(ctx, func(txCtx context.Context) error {
			tenant, err := access.tenant.Get(txCtx, in.ID)
			if err != nil {
				return err
			}
			if base == "repair" {
				if err := access.remember(tenant); err != nil {
					return err
				}
				out.Scope, err = access.root.Write(txCtx, tenant)
				return err
			}
			if base == "activate" {
				tenant.Activate()
			} else {
				tenant.Deactivate()
			}
			return access.tenant.Update(txCtx, tenant)
		})
	}
	return out, err
}

func (s *TenantService) execute(ctx context.Context, action string, input TenantCommandInput) (TenantCommandResult, error) {
	if command := s.commands[action]; command != nil {
		return command.Execute(ctx, tenantCommandInput{TenantCommandInput: input, Action: action})
	}
	return TenantCommandResult{}, errors.NewCode(errors.InvalidInput, "tenant action is not declared")
}
func (s *TenantService) ExecuteHTTP(ctx context.Context, action string, input TenantCommandInput) (TenantCommandResult, error) {
	return s.execute(ctx, "http_"+action, input)
}
func (s *TenantService) AuthorizationBinding(action string) (auth.EntryBinding, error) {
	if command := s.commands[action]; command != nil {
		return command.AuthorizationBinding()
	}
	return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "tenant action is not declared")
}
