package tenant

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
)

func tenantAuthorizationFixture(t *testing.T) (*TenantService, *capturingTenantModel) {
	t.Helper()
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	model := &capturingTenantModel{}
	tenants, err := tenantrepo.NewTenantRepository(&fakeTenantOrm{model: model}, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(tenants.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	resolver := svc.NewScopeAuthorizer(scopes, tenants)
	service, err := NewTenantService(tenants, resolver, svc.NewIAMAccess(resolver))
	if err != nil {
		t.Fatal(err)
	}
	return service, model
}

func tenantPrincipal(t *testing.T, permissions []string, system bool, kind string) context.Context {
	t.Helper()
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", Permissions: permissions, IsSystem: system, ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	return iamauth.BindActiveScopeContext(ctx, 1, kind)
}

func TestTenantCommandsRejectBeforeResourceAccess(t *testing.T) {
	service, model := tenantAuthorizationFixture(t)
	trace, err := contextx.WithUserID(t.Context(), "7")
	if err != nil {
		t.Fatal(err)
	}
	platform := tenantPrincipal(t, []string{"user:api:read"}, false, iamentity.ScopeTypePlatform)
	for _, test := range []struct {
		name string
		ctx  context.Context
		want errors.ErrorCode
	}{
		{"nil", nil, errors.InvalidInput}, {"anonymous", t.Context(), errors.Forbidden},
		{"trace_only", trace, errors.Forbidden}, {"wrong_permission", platform, errors.Forbidden},
		{"tenant_domain", tenantPrincipal(t, []string{"tenant:api:*"}, false, iamentity.ScopeTypeTenant), errors.Forbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			for action := range service.commands {
				beforeReads, beforeWrites := model.reads, model.writes
				_, err := service.execute(test.ctx, action, TenantCommandInput{ID: 99, Create: &svc.CreateTenantRequest{Key: "denied", Name: "Denied"}, Update: &svc.UpdateTenantRequest{Name: "Denied"}})
				if !errors.Is(err, test.want) {
					t.Fatalf("%s: %v, want %s", action, err, test.want)
				}
				if model.reads != beforeReads || model.writes != beforeWrites {
					t.Fatalf("%s touched resources before rejection", action)
				}
			}
		})
	}
}

func TestTenantHTTPRequiresNumericIdentityAndPlatformDomain(t *testing.T) {
	service, model := tenantAuthorizationFixture(t)
	for _, subject := range []string{"", "worker", "0", "-7"} {
		ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: subject, IsSystem: true})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, 1, iamentity.ScopeTypePlatform)
		for _, action := range []string{"activate", "deactivate", "repair"} {
			if _, err := service.ExecuteHTTP(ctx, action, TenantCommandInput{ID: 99}); !errors.Is(err, errors.Unauthorized) {
				t.Fatalf("subject %q action %s: %v", subject, action, err)
			}
		}
	}
	for _, system := range []bool{false, true} {
		ctx := tenantPrincipal(t, []string{"tenant:api:*"}, system, iamentity.ScopeTypeTenant)
		for _, action := range []string{"activate", "deactivate", "repair"} {
			if _, err := service.ExecuteHTTP(ctx, action, TenantCommandInput{ID: 99}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("tenant-domain system=%t action=%s: %v", system, action, err)
			}
		}
	}
	if model.reads != 0 || model.writes != 0 {
		t.Fatal("HTTP rejection touched resources")
	}
	ctx := iamtenant.WithPolicy(tenantPrincipal(t, []string{"tenant:api:*"}, true, iamentity.ScopeTypeTenant), iamtenant.Policy{Mode: iamtenant.ModeSingle})
	if decision, err := (tenantHTTPPolicy{}).Evaluate(ctx, auth.Request{}); err != nil || !decision.Allowed {
		t.Fatalf("single-tenant HTTP exemption: %+v %v", decision, err)
	}
}

type tenantConditionPolicy struct{ condition spec.Spec }

func (p tenantConditionPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByField("ID")}}
}
func (p tenantConditionPolicy) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: true, Spec: p.condition}, nil
}

func tenantCapabilityCommand(t *testing.T, service *TenantService, conditions []spec.Spec, mutate func(*tenantCommandInput), handler func(context.Context, tenantCommandInput, *tenantAccess) (struct{}, error)) *app.Command[tenantCommandInput, *tenantAccess, struct{}] {
	t.Helper()
	_, scopes, err := service.scopeAuthorizer.TenantScopeProviders()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"tenant", "root", "visibility", "link"}
	providers := []app.IExecutionDescriptorProvider{service.tenantRepo, scopes, service.rootProvider, service.tenantRepo}
	resources := make([]app.CommandResource[tenantCommandInput], len(names))
	for i, name := range names {
		resource := svc.TenantResourceKind
		if name == "root" || name == "visibility" {
			resource = svc.ScopeResourceKind
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: "repair", Kind: auth.KindUpdate}}}, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{tenantConditionPolicy{conditions[i]}}}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: providers[i].ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		resources[i] = app.CommandResource[tenantCommandInput]{Name: name, Repository: providers[i], Authorizer: authorizer, Action: "repair", Intent: func(tenantCommandInput) (auth.Request, error) { return auth.Request{}, nil }}
	}
	command, err := app.NewCommand(app.CommandOptions[tenantCommandInput, *tenantAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, in tenantCommandInput, grants []*app.CommandGrant) (*tenantAccess, error) {
			if mutate != nil {
				mutate(&in)
			}
			return service.bindAccess(in, names, grants, scopes)
		}, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestTenantRootCapabilitiesRejectPartialCatalogBeforeReads(t *testing.T) {
	for _, index := range []int{1, 2, 3} {
		service, model := tenantAuthorizationFixture(t)
		conditions := []spec.Spec{spec.All(), spec.All(), spec.All(), spec.All()}
		conditions[index] = spec.Eq(meta.ByField("ID"), int64(9))
		command := tenantCapabilityCommand(t, service, conditions, nil, func(ctx context.Context, _ tenantCommandInput, access *tenantAccess) (struct{}, error) {
			for _, guard := range access.guards {
				if _, err := guard.Read(ctx, struct{}{}); err != nil {
					return struct{}{}, err
				}
			}
			_, err := access.tenant.Get(ctx, 9)
			return struct{}{}, err
		})
		if _, err := command.Execute(tenantPrincipal(t, nil, true, iamentity.ScopeTypePlatform), tenantCommandInput{Action: "repair"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("partial catalog %d: %v", index, err)
		}
		if model.reads != 0 || model.writes != 0 {
			t.Fatal("partial catalog touched resources")
		}
	}
}

func TestTenantRootCapabilitiesCheckActionTargetAndLifetime(t *testing.T) {
	service, model := tenantAuthorizationFixture(t)
	conditions := []spec.Spec{spec.All(), spec.All(), spec.All(), spec.All()}
	ctx := tenantPrincipal(t, nil, true, iamentity.ScopeTypePlatform)
	command := tenantCapabilityCommand(t, service, conditions, func(in *tenantCommandInput) { in.Action = "update" }, func(context.Context, tenantCommandInput, *tenantAccess) (struct{}, error) {
		t.Fatal("mismatched action entered handler")
		return struct{}{}, nil
	})
	if _, err := command.Execute(ctx, tenantCommandInput{Action: "repair"}); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("wrong action: %v", err)
	}
	var retained *tenantAccess
	command = tenantCapabilityCommand(t, service, conditions, nil, func(ctx context.Context, _ tenantCommandInput, access *tenantAccess) (struct{}, error) {
		retained = access
		trusted := iamentity.Tenant{Key: "trusted", Name: "Trusted", Status: svc.TenantStatusInactive}
		trusted.ID = 9
		rootID := int64(3)
		trusted.RootScopeID = &rootID
		if err := access.remember(&trusted); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*iamentity.Tenant){
			func(x *iamentity.Tenant) { x.ID++ }, func(x *iamentity.Tenant) { x.Key = "other" },
			func(x *iamentity.Tenant) { x.Name = "Other" }, func(x *iamentity.Tenant) { x.Description = "Other" },
			func(x *iamentity.Tenant) { x.Status = svc.TenantStatusActive }, func(x *iamentity.Tenant) { x.Version++ },
			func(x *iamentity.Tenant) { x.RootScopeID = nil },
			func(x *iamentity.Tenant) { *x.RootScopeID = 99 },
		} {
			candidate, err := meta.Clone(trusted)
			if err != nil {
				t.Fatal(err)
			}
			change(&candidate)
			if _, err := access.root.Write(ctx, &candidate); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("altered trusted target: %v", err)
			}
		}
		*trusted.RootScopeID = 99
		if *access.trusted[9].RootScopeID != 3 {
			t.Fatal("trusted root scope pointer was shared with its input")
		}
		other := tenantPrincipal(t, nil, true, iamentity.ScopeTypePlatform)
		other, err := hostauthz.WithPrincipal(other, hostauthz.Principal{SubjectID: "8", IsSystem: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.root.Write(other, &trusted); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("switched identity: %v", err)
		}
		return struct{}{}, nil
	})
	if _, err := command.Execute(ctx, tenantCommandInput{Action: "repair"}); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.root.Write(ctx, nil); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired capability: %v", err)
	}
	if model.reads != 0 || model.writes != 0 {
		t.Fatal("invalid capability touched resources")
	}
}

func TestTenantConstructionAndBindingsUseActualProviders(t *testing.T) {
	service, _ := tenantAuthorizationFixture(t)
	if _, err := NewTenantService(nil, service.scopeAuthorizer, service.authorizer); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing tenant: %v", err)
	}
	if _, err := NewTenantService(service.tenantRepo, nil, service.authorizer); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing scope: %v", err)
	}
	if _, err := NewTenantService(service.tenantRepo, service.scopeAuthorizer, nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing declaration: %v", err)
	}
	other, _ := tenantAuthorizationFixture(t)
	if _, err := NewTenantService(service.tenantRepo, other.scopeAuthorizer, service.authorizer); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("different actual tenant: %v", err)
	}
	for action := range service.commands {
		binding, err := service.AuthorizationBinding(action)
		if err != nil {
			t.Fatal(err)
		}
		binding.Entry = auth.Entry{Kind: "service", Key: "tenant." + action}
		report, err := auth.ValidateEntries([]auth.Entry{binding.Entry}, []auth.EntryBinding{binding})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		want := 1
		if action == "create" {
			want = 5
		}
		if action == "repair" || action == "http_repair" {
			want = 4
		}
		if len(report) != 1 || len(report[0].Resources)+1 != want {
			t.Fatalf("%s resources=%+v", action, report)
		}
	}
	if _, err := service.AuthorizationBinding("undeclared"); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("unknown action: %v", err)
	}
}
