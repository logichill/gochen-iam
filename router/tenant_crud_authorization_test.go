package router

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	"gochen/contextx"
	"gochen/db/orm"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
)

// Observe the actual Lite model/transaction path used by these repositories.
// A successful control read proves the observer is attached to business access.
type tenantObservedOrm struct {
	orm.IOrm
	models, transactions *atomic.Int64
}

func (o *tenantObservedOrm) DatasourceID() string { id, _ := orm.DatasourceIDOf(o.IOrm); return id }
func (o *tenantObservedOrm) Model(metadata *orm.ModelMeta) (orm.IModel, error) {
	o.models.Add(1)
	return o.IOrm.Model(metadata)
}
func (o *tenantObservedOrm) WithContext(ctx context.Context) orm.IOrm {
	return &tenantObservedOrm{IOrm: o.IOrm.WithContext(ctx), models: o.models, transactions: o.transactions}
}
func (o *tenantObservedOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	o.transactions.Add(1)
	session, err := o.IOrm.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &tenantObservedSession{IOrmSession: session, models: o.models}, nil
}
func (o *tenantObservedOrm) BeginTx(ctx context.Context, options *sql.TxOptions) (orm.IOrmSession, error) {
	o.transactions.Add(1)
	session, err := o.IOrm.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &tenantObservedSession{IOrmSession: session, models: o.models}, nil
}

type tenantObservedSession struct {
	orm.IOrmSession
	models *atomic.Int64
}

func (s *tenantObservedSession) DatasourceID() string {
	id, _ := orm.DatasourceIDOf(s.IOrmSession)
	return id
}
func (s *tenantObservedSession) Model(metadata *orm.ModelMeta) (orm.IModel, error) {
	s.models.Add(1)
	return s.IOrmSession.Model(metadata)
}

func tenantObservedFixture(t *testing.T) (*TenantRoutes, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	routes, storage := tenantRoutesFixture(t)
	models, transactions := &atomic.Int64{}, &atomic.Int64{}
	engine := &tenantObservedOrm{IOrm: routes.scopeRepo.Orm(), models: models, transactions: transactions}
	tenants, err := tenantrepo.NewTenantRepository(engine, testkit.NewInt64Sequence(100))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	groups, err := grouprepo.NewGroupRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	resolver := svc.NewScopeAuthorizer(scopes, tenants)
	access := svc.NewIAMAccess(resolver)
	service, err := tenantsvc.NewTenantService(tenants, resolver, access)
	if err != nil {
		t.Fatal(err)
	}
	routes, err = NewTenantRoutes(service, tenants, resolver, access, users, groups, roles, scopes)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"first", "second"} {
		tenant := &iamentity.Tenant{Key: key, Name: key, Status: svc.TenantStatusInactive}
		tenant.ID = int64(100 + i)
		if err := storage.Create(tenant).Error; err != nil {
			t.Fatal(err)
		}
	}
	models.Store(0)
	transactions.Store(0)
	return routes, models, transactions
}

type tenantCRUDTestPolicy struct {
	condition spec.Spec
	denied    bool
}

func (p tenantCRUDTestPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ID()}}
}
func (p tenantCRUDTestPolicy) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: !p.denied, Spec: p.condition}, nil
}
func tenantTestResources(t *testing.T, a *tenantCRUDApplication, action string, conditions map[string]spec.Spec, deny string) []app.CommandResource[tenantCRUDInput] {
	t.Helper()
	resources := append([]app.CommandResource[tenantCRUDInput](nil), a.resources[action]...)
	for i, resource := range resources {
		plan, _ := resource.Authorizer.Plan()
		condition := spec.All()
		if override, ok := conditions[resource.Name]; ok {
			condition = override
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: plan.Descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "test." + resource.Name, System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{tenantCRUDTestPolicy{condition: condition, denied: resource.Name == deny}}}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: resource.Repository.ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		resources[i].Authorizer = authorizer
	}
	return resources
}

func TestTenantCRUDDenialsAndEveryLaterResourceHaveZeroAccess(t *testing.T) {
	routes, models, transactions := tenantObservedFixture(t)
	ctx := tenantCRUDPrincipal(t)
	if _, err := routes.standard.Get(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if models.Load() == 0 || transactions.Load() == 0 {
		t.Fatal("observer did not see the successful actual path")
	}
	models.Store(0)
	transactions.Store(0)
	trace, err := contextx.WithUserID(t.Context(), "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []context.Context{nil, t.Context(), trace} {
		if _, err := routes.standard.Get(denied, 100); err == nil {
			t.Fatal("untrusted read allowed")
		}
		if _, err := routes.standard.Query(denied, query.QueryOptions{}); err == nil {
			t.Fatal("untrusted list allowed")
		}
		if _, err := routes.standard.QueryCount(denied, query.QueryOptions{}); err == nil {
			t.Fatal("untrusted count allowed")
		}
		if err := routes.standard.Create(denied, &tenantHTTPModel{Tenant: iamentity.Tenant{Key: "denied", Name: "Denied"}}); err == nil {
			t.Fatal("untrusted create allowed")
		}
		if err := routes.standard.Delete(denied, 100); err == nil {
			t.Fatal("untrusted delete allowed")
		}
	}
	for action, original := range routes.standard.application.resources {
		for _, resource := range original {
			t.Run(action+"/"+resource.Name, func(t *testing.T) {
				routes.standard.application.resources[action] = tenantTestResources(t, routes.standard.application, action, nil, resource.Name)
				called := false
				_, err := routes.standard.application.execute(ctx, action, []int64{100}, func(context.Context, *tenantCRUDAccess) (tenantCRUDResult, error) {
					called = true
					return tenantCRUDResult{}, nil
				})
				routes.standard.application.resources[action] = original
				if !errors.Is(err, errors.Forbidden) || called {
					t.Fatalf("later resource denial error=%v handler=%t", err, called)
				}
			})
		}
	}
	if models.Load() != 0 || transactions.Load() != 0 {
		t.Fatalf("denied actual models=%d transactions=%d", models.Load(), transactions.Load())
	}
}

func TestTenantCRUDIndependentPrimarySnapshotAndCompleteCatalogConditions(t *testing.T) {
	routes, models, transactions := tenantObservedFixture(t)
	a := routes.standard.application
	ctx := tenantCRUDPrincipal(t)
	for _, action := range []string{appcrud.ActionRead, appcrud.ActionList, appcrud.ActionCreate, appcrud.ActionUpdate, appcrud.ActionDelete} {
		original := a.resources[action]
		for _, resource := range original {
			if resource.Name == "tenant" || resource.Name == "snapshot" {
				continue
			}
			a.resources[action] = tenantTestResources(t, a, action, map[string]spec.Spec{resource.Name: spec.In(meta.ID())}, "")
			_, err := a.execute(ctx, action, []int64{100}, func(context.Context, *tenantCRUDAccess) (tenantCRUDResult, error) { return tenantCRUDResult{}, nil })
			a.resources[action] = original
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("partial %s/%s catalog allowed: %v", action, resource.Name, err)
			}
		}
	}
	if models.Load() != 0 || transactions.Load() != 0 {
		t.Fatalf("partial catalog reads=%d transactions=%d", models.Load(), transactions.Load())
	}
	original := a.resources[appcrud.ActionList]
	a.resources[appcrud.ActionList] = tenantTestResources(t, a, appcrud.ActionList, map[string]spec.Spec{"tenant": spec.In(meta.ID(), int64(101))}, "")
	items, err := routes.standard.List(ctx, 0, 1)
	if err != nil || len(items) != 1 || items[0].ID != 101 {
		t.Fatalf("primary independent condition items=%+v error=%v", items, err)
	}
	count, err := routes.standard.Count(ctx)
	if err != nil || count != 1 {
		t.Fatalf("count lost primary condition=%d error=%v", count, err)
	}
	a.resources[appcrud.ActionList] = original
	original = a.resources[appcrud.ActionUpdate]
	a.resources[appcrud.ActionUpdate] = tenantTestResources(t, a, appcrud.ActionUpdate, map[string]spec.Spec{"snapshot": spec.Eq(meta.ID(), int64(101))}, "")
	called := false
	_, err = routes.standard.Execute(ctx, appcrud.ActionUpdate, 100, func(_ context.Context, item *tenantHTTPModel) error {
		called = true
		item.Name = "Denied snapshot"
		return nil
	})
	a.resources[appcrud.ActionUpdate] = original
	if !errors.Is(err, errors.NotFound) || !called {
		t.Fatalf("independent snapshot condition error=%v business=%t", err, called)
	}
	item, err := routes.standard.Get(ctx, 100)
	if err != nil || item.Name != "first" || item.Version != 0 {
		t.Fatalf("denied snapshot modified tenant=%+v error=%v", item, err)
	}
}

func TestTenantCRUDCapabilitiesKeepTargetsIdentityAndLifetime(t *testing.T) {
	routes, _, _ := tenantObservedFixture(t)
	a := routes.standard.application
	ctx := tenantCRUDPrincipal(t)
	var retained *tenantCRUDAccess
	var port *appcrud.Application[*iamentity.Tenant, int64]
	_, err := a.execute(ctx, appcrud.ActionRead, []int64{100}, func(ctx context.Context, access *tenantCRUDAccess) (tenantCRUDResult, error) {
		retained, port = access, access.core
		item, err := access.core.Get(ctx, 100)
		if err != nil {
			return tenantCRUDResult{}, err
		}
		if _, err := access.core.Get(ctx, 101); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("other target read=%v", err)
		}
		if _, err := access.catalog.Write(ctx, tenantCatalogCall{ID: 101, Operation: "health"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("unknown tenant projection=%v", err)
		}
		if _, err := access.governance.State(ctx, &iamentity.Tenant{Key: "second", Status: svc.TenantStatusInactive}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("unknown tenant occupancy=%v", err)
		}
		if _, err := access.catalog.Write(ctx, tenantCatalogCall{ID: 100, Operation: "provision"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("read provision=%v", err)
		}
		changed, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"tenant:api:read"}})
		if err != nil {
			t.Fatal(err)
		}
		changed = iamauth.BindActiveScopeContext(changed, 1, "platform")
		if _, err := access.catalog.Write(changed, tenantCatalogCall{ID: 100, Operation: "health"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("changed identity=%v", err)
		}
		changed, err = contextx.WithTenantID(ctx, "other")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.catalog.Write(changed, tenantCatalogCall{ID: 100, Operation: "health"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("changed tenant=%v", err)
		}
		// Returned entities are independent of the command's private relation map.
		item.Key = "second"
		if access.trusted[100].Key != "first" {
			t.Fatal("returned entity mutated trusted relation")
		}
		return tenantCRUDResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retained.catalog.Write(ctx, tenantCatalogCall{ID: 100, Operation: "health"}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired catalog=%v", err)
	}
	if _, err := port.Get(ctx, 100); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired primary=%v", err)
	}
	for action, original := range a.resources {
		for i, resource := range original {
			resources := append([]app.CommandResource[tenantCRUDInput](nil), original...)
			resources[i].Repository = &tenantVisibilityCatalog{execution: resource.Repository.ExecutionDescriptor()}
			a.resources[action] = resources
			_, err := a.execute(ctx, action, []int64{100}, func(context.Context, *tenantCRUDAccess) (tenantCRUDResult, error) { return tenantCRUDResult{}, nil })
			a.resources[action] = original
			if !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("replaced provider %s/%s error=%v", action, resource.Name, err)
			}
		}
	}
	t.Log("tenant primary and derived capability lifecycle verified")
}

func TestTenantCRUDConstructionRejectsMissingAndChangedSources(t *testing.T) {
	routes, models, _ := tenantObservedFixture(t)
	for _, name := range []string{"tenant", "scope", "user", "group", "role", "scope_authorizer", "authorizer"} {
		fixed := *routes
		switch name {
		case "tenant":
			fixed.tenantRepo = nil
		case "scope":
			fixed.scopeRepo = nil
		case "user":
			fixed.userRepo = nil
		case "group":
			fixed.groupRepo = nil
		case "role":
			fixed.roleRepo = nil
		case "scope_authorizer":
			fixed.scopeAuthorizer = nil
		case "authorizer":
			fixed.authorizer = nil
		}
		if _, err := newTenantCRUDApplication(&fixed); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("missing %s source=%v", name, err)
		}
	}
	replacement, _, _ := tenantObservedFixture(t)
	for _, name := range []string{"tenant", "scope", "user"} {
		fixed := *routes
		switch name {
		case "tenant":
			fixed.tenantRepo = replacement.tenantRepo
		case "scope":
			fixed.scopeRepo = replacement.scopeRepo
		case "user":
			fixed.userRepo = replacement.userRepo
		}
		if _, err := newTenantCRUDApplication(&fixed); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("changed %s source=%v", name, err)
		}
	}
	var typedNil *tenantsvc.TenantService
	if _, err := NewTenantRoutes(typedNil, routes.tenantRepo, routes.scopeAuthorizer, routes.authorizer, routes.userRepo, routes.groupRepo, routes.roleRepo, routes.scopeRepo); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("typed nil service=%v", err)
	}
	if models.Load() != 0 {
		t.Fatalf("failed constructor accessed models=%d", models.Load())
	}
}
