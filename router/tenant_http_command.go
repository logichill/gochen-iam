package router

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type tenantCRUDInput struct{ IDs []int64 }
type tenantCRUDResult struct {
	Items []*iamentity.Tenant
	Views []svc.TenantListItem
	Count int64
}
type tenantCatalogCall struct {
	ID        int64
	Operation string
}
type tenantCatalogResult struct {
	Root   *iamentity.Scope
	Health *svc.TenantRootScopeHealth
}

type tenantCRUDEntryPolicy struct{}

func (tenantCRUDEntryPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (tenantCRUDEntryPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
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

// The native visibility projection is owned by the same actual ScopeRepo.
type tenantVisibilityCatalog struct {
	execution app.ExecutionDescriptor
	owner     app.IExecutionDescriptorProvider
}
type tenantVisibilityItem struct {
	ID string `entity:"id"`
}

func (p *tenantVisibilityCatalog) ExecutionDescriptor() app.ExecutionDescriptor { return p.execution }

type tenantCRUDApplication struct {
	routes     *TenantRoutes
	options    appcrud.Options[*iamentity.Tenant, int64]
	core       *appcrud.Application[*iamentity.Tenant, int64]
	resources  map[string][]app.CommandResource[tenantCRUDInput]
	visibility *tenantVisibilityCatalog
}
type tenantCRUDAccess struct {
	core       *appcrud.Application[*iamentity.Tenant, int64]
	known      map[int64]bool
	trusted    map[int64]iamentity.Tenant
	roots      map[int64]iamentity.Scope
	guards     []*app.CommandReader[struct{}, struct{}]
	governance *tenantDeleteGovernance
	catalog    *app.CommandWriter[tenantCatalogCall, tenantCatalogResult]
}

func tenantCRUDResourceNames(action string) []string {
	switch action {
	case appcrud.ActionCreate:
		return []string{"tenant", "root", "visibility", "link"}
	case appcrud.ActionUpdate:
		return []string{"tenant", "snapshot", "users", "groups", "roles", "root", "visibility"}
	case appcrud.ActionRead, appcrud.ActionList, appcrud.ActionDelete:
		return []string{"tenant", "users", "groups", "roles", "root", "visibility"}
	default:
		return nil
	}
}

func newTenantCRUDApplication(tr *TenantRoutes) (*tenantCRUDApplication, error) {
	if tr == nil || tr.tenantRepo == nil || tr.tenantRepo.Repo == nil || tr.scopeAuthorizer == nil || tr.authorizer == nil ||
		tr.userRepo == nil || tr.userRepo.Repo == nil || tr.groupRepo == nil || tr.groupRepo.Repo == nil ||
		tr.roleRepo == nil || tr.roleRepo.Repo == nil || tr.scopeRepo == nil || tr.scopeRepo.Repo == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant CRUD requires all actual governance repositories")
	}
	provider := app.IExecutionDescriptorProvider(tr.tenantRepo)
	tenants, scopes, err := tr.scopeAuthorizer.TenantScopeProviders()
	if err != nil {
		return nil, err
	}
	// Provisioning writes the base tenant port; reject replacement sources at construction.
	if scopes != tr.scopeRepo.Repo {
		return nil, errors.NewCode(errors.InvalidInput, "tenant governance scope source differs from provisioning")
	}
	if tenants != tr.tenantRepo.Repo {
		return nil, errors.NewCode(errors.InvalidInput, "tenant governance source differs from provisioning")
	}
	for _, source := range []interface{ DataSourceID() string }{tr.userRepo, tr.groupRepo, tr.roleRepo, tr.scopeRepo} {
		if source.DataSourceID() != tr.tenantRepo.DataSourceID() {
			return nil, errors.NewCode(errors.InvalidInput, "tenant governance requires one transaction datasource")
		}
	}
	options := appcrud.Options[*iamentity.Tenant, int64]{Resource: "tenant", ActionPermissions: map[string]string{
		appcrud.ActionRead: "tenant:api:read", appcrud.ActionList: "tenant:api:read", appcrud.ActionCreate: "tenant:api:write",
		appcrud.ActionUpdate: "tenant:api:write", appcrud.ActionDelete: "tenant:api:delete",
	}}
	descriptor, err := appcrud.Describe(options, true)
	if err != nil {
		return nil, err
	}
	primary, err := tr.authorizer.Compile(descriptor, provider.ExecutionDescriptor().Metadata(), tenantCRUDEntryPolicy{})
	if err != nil {
		return nil, err
	}
	options.Authorizer = primary
	core, err := appcrud.NewApplication(tr.tenantRepo, options)
	if err != nil {
		return nil, err
	}
	metadata, err := meta.Describe[*tenantVisibilityItem]()
	if err != nil {
		return nil, err
	}
	execution, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		return nil, err
	}
	fixed := *tr
	a := &tenantCRUDApplication{routes: &fixed, options: options, core: core, resources: map[string][]app.CommandResource[tenantCRUDInput]{},
		visibility: &tenantVisibilityCatalog{execution: execution, owner: tr.scopeRepo.Repo}}
	for _, action := range []string{appcrud.ActionRead, appcrud.ActionList, appcrud.ActionCreate, appcrud.ActionUpdate, appcrud.ActionDelete} {
		names := tenantCRUDResourceNames(action)
		for _, name := range names {
			source, resource, kind := provider, "tenant", auth.KindRead
			switch name {
			case "tenant":
				for _, item := range descriptor.Actions {
					if item.Name == action {
						kind = item.Kind
					}
				}
			case "snapshot", "link":
				resource = svc.TenantResourceKind
			case "users":
				source, resource = tr.userRepo.Repo, "iam.tenant.user_occupancy"
			case "groups":
				source, resource = tr.groupRepo.Repo, "iam.tenant.group_occupancy"
			case "roles":
				source, resource = tr.roleRepo.Repo, "iam.tenant.role_occupancy"
			case "root":
				source, resource, kind = tr.scopeRepo.Repo, svc.ScopeResourceKind, auth.KindUpdate
			case "visibility":
				source, resource, kind = a.visibility, svc.ScopeResourceKind, auth.KindUpdate
			}
			if name == "link" {
				kind = auth.KindUpdate
			}
			permission := options.ActionPermissions[action]
			nameAction := "http_" + action + "_" + name
			authorizer := primary
			if name == "tenant" {
				nameAction = action
			} else {
				d := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: nameAction, Kind: kind, Permission: permission}}}
				if name == "users" || name == "groups" || name == "roles" {
					authorizer, err = auth.Compile(auth.Declaration{Descriptor: d, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: []auth.IPolicy{tenantCRUDEntryPolicy{}}}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: source.ExecutionDescriptor().Metadata()})
				} else {
					authorizer, err = tr.authorizer.Compile(d, source.ExecutionDescriptor().Metadata(), tenantCRUDEntryPolicy{})
				}
				if err != nil {
					return nil, err
				}
			}
			primaryTarget := name == "tenant" || name == "snapshot"
			a.resources[action] = append(a.resources[action], app.CommandResource[tenantCRUDInput]{Name: name, Repository: source, Authorizer: authorizer, Action: nameAction,
				ConditionPath: "Command capabilities -> actual per-resource Spec before primary reads, pagination and native catalogs; frozen tenant/root relations -> governed projection or same-transaction root/visibility/link write",
				Intent: func(in tenantCRUDInput) (auth.Request, error) {
					if !primaryTarget || action == appcrud.ActionCreate || action == appcrud.ActionList {
						return auth.Request{}, nil
					}
					ids := make([]string, 0, len(in.IDs))
					for _, id := range in.IDs {
						if id <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "tenant ID must be positive")
						}
						ids = append(ids, strconv.FormatInt(id, 10))
					}
					return auth.Request{IDs: ids}, nil
				}})
		}
		command, err := a.command(action, nil)
		if err != nil {
			return nil, err
		}
		if _, err := command.AuthorizationBinding(); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *tenantCRUDApplication) command(action string, invoke func(context.Context, *tenantCRUDAccess) (tenantCRUDResult, error)) (*app.Command[tenantCRUDInput, *tenantCRUDAccess, tenantCRUDResult], error) {
	resources := a.resources[action]
	if len(resources) == 0 {
		return nil, errors.NewCode(errors.InvalidInput, "tenant CRUD action is not declared")
	}
	return app.NewCommand(app.CommandOptions[tenantCRUDInput, *tenantCRUDAccess, tenantCRUDResult]{Resources: resources,
		Access: func(_ context.Context, in tenantCRUDInput, grants []*app.CommandGrant) (*tenantCRUDAccess, error) {
			return a.bind(action, in, grants)
		},
		Handler: func(ctx context.Context, _ tenantCRUDInput, access *tenantCRUDAccess) (tenantCRUDResult, error) {
			for _, guard := range access.guards {
				if _, err := guard.Read(ctx, struct{}{}); err != nil {
					return tenantCRUDResult{}, err
				}
			}
			if invoke == nil {
				return tenantCRUDResult{}, errors.NewCode(errors.InvalidInput, "tenant CRUD invocation is required")
			}
			var output tenantCRUDResult
			err := a.routes.tenantRepo.WithinTx(ctx, func(txCtx context.Context) error {
				var err error
				output, err = invoke(txCtx, access)
				return err
			})
			return output, err
		}})
}

func (a *tenantCRUDAccess) remember(item *iamentity.Tenant) error {
	if item == nil || item.ID <= 0 {
		return errors.NewCode(errors.InvalidInput, "trusted tenant is required")
	}
	frozen, err := meta.Clone(*item)
	if err != nil {
		return err
	}
	a.trusted[item.ID] = frozen
	return nil
}
func (a *tenantCRUDAccess) trustedKey(key string) bool {
	for _, item := range a.trusted {
		if strings.TrimSpace(item.Key) == key && key != "" {
			return true
		}
	}
	return false
}
func (a *tenantCRUDAccess) trustedRoot(id int64) bool {
	for _, item := range a.trusted {
		if item.RootScopeID != nil && *item.RootScopeID == id {
			return true
		}
	}
	return false
}

func (a *tenantCRUDAccess) ownsRoot(root iamentity.Scope) bool {
	if root.Type != iamentity.ScopeTypeTenant {
		return false
	}
	for _, tenant := range a.trusted {
		if tenant.RootScopeID != nil && *tenant.RootScopeID == root.ID && root.Key == "tenant:"+strings.TrimSpace(tenant.Key) {
			return true
		}
	}
	return false
}

func (a *tenantCRUDApplication) bind(action string, in tenantCRUDInput, grants []*app.CommandGrant) (*tenantCRUDAccess, error) {
	resources := a.resources[action]
	names := tenantCRUDResourceNames(action)
	if len(names) == 0 || len(resources) != len(names) || len(grants) != len(resources) {
		return nil, errors.NewCode(errors.InvalidInput, "tenant CRUD requires every declared capability")
	}
	access := &tenantCRUDAccess{known: map[int64]bool{}, trusted: map[int64]iamentity.Tenant{}, roots: map[int64]iamentity.Scope{}, governance: &tenantDeleteGovernance{}}
	for _, id := range in.IDs {
		access.known[id] = true
	}
	byName := map[string]*app.CommandGrant{}
	for i, resource := range resources {
		if resource.Name != names[i] {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability order differs from declaration")
		}
		provider, expectedResource := app.IExecutionDescriptorProvider(a.routes.tenantRepo), "tenant"
		switch resource.Name {
		case "tenant":
		case "snapshot", "link":
			expectedResource = svc.TenantResourceKind
		case "users":
			provider, expectedResource = a.routes.userRepo.Repo, "iam.tenant.user_occupancy"
		case "groups":
			provider, expectedResource = a.routes.groupRepo.Repo, "iam.tenant.group_occupancy"
		case "roles":
			provider, expectedResource = a.routes.roleRepo.Repo, "iam.tenant.role_occupancy"
		case "root":
			provider, expectedResource = a.routes.scopeRepo.Repo, svc.ScopeResourceKind
		case "visibility":
			provider, expectedResource = a.visibility, svc.ScopeResourceKind
		default:
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability name is not declared")
		}
		if resource.Repository != provider {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability provider differs from actual source")
		}
		grant := grants[i]
		if grant == nil || grant.Name() != resource.Name {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability differs from declaration")
		}
		request, err := grant.Request()
		if err != nil {
			return nil, err
		}
		expectedAction := "http_" + action + "_" + resource.Name
		if resource.Name == "tenant" {
			expectedAction = action
		}
		if request.Action != expectedAction || request.Resource != expectedResource || len(request.Targets) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability action/resource/targets differ from declaration")
		}
		expected := 0
		if (resource.Name == "tenant" || resource.Name == "snapshot") && action != appcrud.ActionCreate && action != appcrud.ActionList {
			expected = len(in.IDs)
		}
		if len(request.IDs) != expected {
			return nil, errors.NewCode(errors.InvalidInput, "tenant capability IDs differ from declaration")
		}
		for j, id := range request.IDs {
			if id != strconv.FormatInt(in.IDs[j], 10) {
				return nil, errors.NewCode(errors.InvalidInput, "tenant capability ID differs from intent")
			}
		}
		byName[resource.Name] = grant
		if resource.Name != "tenant" && resource.Name != "snapshot" {
			guard, err := app.NewCommandReader(resource.Repository, grant, func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
				if !condition.IsAll() {
					return struct{}{}, errors.NewCode(errors.Forbidden, "tenant governance requires the complete authorized catalog")
				}
				return struct{}{}, nil
			})
			if err != nil {
				return nil, err
			}
			access.guards = append(access.guards, guard)
		}
	}
	port, err := a.bindPrimary(action, access, byName["tenant"])
	if err != nil {
		return nil, err
	}
	options := a.options
	options.Hooks = appcrud.Hooks[*iamentity.Tenant]{}
	if action == appcrud.ActionCreate {
		options.Hooks[appcrud.ActionCreate] = appcrud.Stage[*iamentity.Tenant]{Before: func(_ context.Context, item *iamentity.Tenant) error { item.RootScopeID = nil; return nil }, After: func(ctx context.Context, item *iamentity.Tenant) error {
			if err := access.remember(item); err != nil {
				return err
			}
			if _, err := access.catalog.Write(ctx, tenantCatalogCall{ID: item.ID, Operation: "provision"}); err != nil {
				return err
			}
			current, err := port.Get(ctx, item.ID, spec.All())
			if err == nil {
				*item = *current
			}
			return err
		}}
	}
	if action == appcrud.ActionUpdate {
		snapshot, err := app.NewCommandReader(a.routes.tenantRepo, byName["snapshot"], func(ctx context.Context, id int64, condition spec.Spec) (*iamentity.Tenant, error) {
			if !access.known[id] {
				return nil, errors.NewCode(errors.Forbidden, "tenant update snapshot is outside its intent")
			}
			return a.routes.tenantRepo.Get(ctx, id, condition)
		})
		if err != nil {
			return nil, err
		}
		options.Hooks[appcrud.ActionUpdate] = appcrud.Stage[*iamentity.Tenant]{Before: func(ctx context.Context, item *iamentity.Tenant) error {
			current, err := snapshot.Read(ctx, item.ID)
			if err != nil {
				return err
			}
			item.RootScopeID = current.RootScopeID
			return nil
		}}
	}
	if action == appcrud.ActionDelete {
		options.Hooks[appcrud.ActionDelete] = appcrud.Stage[*iamentity.Tenant]{Before: func(ctx context.Context, item *iamentity.Tenant) error {
			trusted, known := access.trusted[item.ID]
			if !known || item.Key != trusted.Key || !sameTenantRootID(item.RootScopeID, trusted.RootScopeID) || item.Status != trusted.Status || item.Version != trusted.Version {
				return errors.NewCode(errors.Forbidden, "tenant deletion differs from its persisted snapshot")
			}
			return access.governance.PrepareDelete(ctx, item)
		}}
	}
	if err := a.bindGovernance(action, access, byName); err != nil {
		return nil, err
	}
	access.core, err = appcrud.NewApplication[*iamentity.Tenant, int64](port, options)
	return access, err
}

func sameTenantRootID(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (a *tenantCRUDApplication) execute(ctx context.Context, action string, ids []int64, invoke func(context.Context, *tenantCRUDAccess) (tenantCRUDResult, error)) (tenantCRUDResult, error) {
	command, err := a.command(action, invoke)
	if err != nil {
		return tenantCRUDResult{}, err
	}
	return command.Execute(ctx, tenantCRUDInput{IDs: ids})
}
