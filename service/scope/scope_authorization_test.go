package scope

import (
	"context"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func countScopeQueries(t *testing.T, storage *gorm.DB) *atomic.Int64 {
	t.Helper()
	counter := &atomic.Int64{}
	if err := storage.Callback().Query().Before("gorm:query").Register("scope:test:queries", func(*gorm.DB) { counter.Add(1) }); err != nil {
		t.Fatal(err)
	}
	return counter
}

func TestScopeCommandsDenyBeforeDatabaseAccess(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	queries := countScopeQueries(t, env.db)
	trace, err := contextx.WithUserID(t.Context(), "7")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", Permissions: []string{"user:api:read"}, ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	reader = iamauth.BindActiveScopeContext(reader, 1, iamentity.ScopeTypePlatform)
	for _, test := range []struct {
		name string
		ctx  context.Context
		want errors.ErrorCode
	}{
		{"nil", nil, errors.InvalidInput}, {"anonymous", t.Context(), errors.Unauthorized}, {"trace", trace, errors.Unauthorized}, {"missing_wildcard", reader, errors.Forbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			for action := range env.scopeService.commands {
				before := queries.Load()
				_, err := env.scopeService.execute(test.ctx, action, ScopeCommandInput{ID: 99, Create: &svc.CreateScopeRequest{Key: "denied", Name: "Denied", Type: "region", ParentID: 1}, Update: &svc.UpdateScopeRequest{Name: "Denied"}})
				if !errors.Is(err, test.want) {
					t.Fatalf("%s error=%v", action, err)
				}
				if queries.Load() != before {
					t.Fatalf("%s read business or fact data before rejection", action)
				}
			}
		})
	}
}

func TestScopeSingleTenantReadAndSystemWriteConstraints(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	root := env.platformScope(t)
	_, child := env.createTenant(t, "bounded", "Bounded")
	for _, system := range []bool{false, true} {
		ctx, err := hostauthz.WithPrincipal(tenant.WithPolicy(t.Context(), tenant.Policy{Mode: tenant.ModeSingle}), hostauthz.Principal{SubjectID: "7", Permissions: []string{"*:*:*"}, IsSystem: system, ActiveScopeID: child.ID})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, child.ID, iamentity.ScopeTypeTenant)
		if _, err := env.scopeService.ExecuteHTTP(ctx, "list", ScopeCommandInput{}); err != nil {
			t.Fatalf("single read system=%t: %v", system, err)
		}
		if _, err := env.scopeService.ExecuteHTTP(ctx, "create", ScopeCommandInput{Create: &svc.CreateScopeRequest{Key: "outside", Name: "Outside", Type: "region", ParentID: root.ID}}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("single write system=%t: %v", system, err)
		}
		multi := tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeTenant})
		if _, err := env.scopeService.ExecuteHTTP(multi, "list", ScopeCommandInput{}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("multi read system=%t: %v", system, err)
		}
	}
	missing, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", IsSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.scopeService.CreateScope(missing, &svc.CreateScopeRequest{Key: "missing", Name: "Missing", Type: "region", ParentID: root.ID}); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("missing active=%v", err)
	}
	unnamed, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{IsSystem: true, ActiveScopeID: root.ID})
	if err != nil {
		t.Fatal(err)
	}
	unnamed = iamauth.BindActiveScopeContext(unnamed, root.ID, iamentity.ScopeTypePlatform)
	if _, err := env.scopeService.ExecuteHTTP(unnamed, "list", ScopeCommandInput{}); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("HTTP system without user=%v", err)
	}
}

func TestScopeWritesReusePlatformFactAndRollbackVisibilityFailure(t *testing.T) {
	for _, action := range []string{"create", "delete"} {
		t.Run(action, func(t *testing.T) {
			env := setupScopeServiceTest(t)
			defer env.teardown(t)
			root := env.platformScope(t)
			input := ScopeCommandInput{Create: &svc.CreateScopeRequest{Key: "atomic", Name: "Atomic", Type: "region", ParentID: root.ID}}
			if action == "delete" {
				created, err := env.scopeService.CreateScope(env.backgroundCtx, input.Create)
				if err != nil {
					t.Fatal(err)
				}
				input.ID = created.ID
			}
			var before []*iamentity.ScopeVisibility
			if err := env.db.Order("viewer_scope_id, target_scope_id").Find(&before).Error; err != nil {
				t.Fatal(err)
			}
			if err := env.db.Exec(`CREATE TRIGGER fail_scope_visibility BEFORE INSERT ON scope_visibility_map BEGIN SELECT RAISE(ABORT, 'injected visibility failure'); END`).Error; err != nil {
				t.Fatal(err)
			}
			factReads := &atomic.Int64{}
			if err := env.db.Callback().Query().Before("gorm:query").Register("scope:test:fact", func(tx *gorm.DB) {
				if tx.Statement.Table == "scope_visibility_map" {
					factReads.Add(1)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := env.scopeService.execute(env.backgroundCtx, action, input); err == nil {
				t.Fatal("expected visibility failure")
			}
			if factReads.Load() != 1 {
				t.Fatalf("coverage fact reads=%d, expected one across all resources", factReads.Load())
			}
			var count int64
			if err := env.db.Model(&iamentity.Scope{}).Where("key = ? AND deleted_at IS NULL", "atomic").Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if action == "delete" {
				want = 1
			}
			if count != want {
				t.Fatalf("scope write escaped rollback: count=%d want=%d", count, want)
			}
			var after []*iamentity.ScopeVisibility
			if err := env.db.Order("viewer_scope_id, target_scope_id").Find(&after).Error; err != nil {
				t.Fatal(err)
			}
			if len(before) != len(after) {
				t.Fatalf("visibility rollback size=%d, want %d", len(after), len(before))
			}
			for i := range before {
				if *before[i] != *after[i] {
					t.Fatal("visibility rollback changed rows")
				}
			}
		})
	}
}

type scopeConditionPolicy struct{ condition spec.Spec }

func (p scopeConditionPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByField("ID")}}
}
func (p scopeConditionPolicy) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: true, Spec: p.condition}, nil
}

func scopeCapabilityCommand(t *testing.T, s *ScopeService, in scopeCommandInput, names []string, conditions []spec.Spec, providers []app.IExecutionDescriptorProvider, access func(context.Context, scopeCommandInput, []*app.CommandGrant) (*scopeAccess, error), handler func(context.Context, scopeCommandInput, *scopeAccess) (struct{}, error)) *app.Command[scopeCommandInput, *scopeAccess, struct{}] {
	t.Helper()
	resources := make([]app.CommandResource[scopeCommandInput], len(names))
	for i, name := range names {
		kind := auth.KindUpdate
		if in.Action == "http_list" || in.Action == "http_visibility" {
			kind = auth.KindRead
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.scope." + name, Actions: []auth.Action{{Name: in.Action, Kind: kind, Permission: svc.AdminEntryPermission.Code}}}, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "test", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{scopeConditionPolicy{conditions[i]}}}}}, auth.CompileOptions{Metadata: providers[i].ExecutionDescriptor().Metadata(), Checker: hostauthz.NewActionChecker()})
		if err != nil {
			t.Fatal(err)
		}
		resources[i] = app.CommandResource[scopeCommandInput]{Name: name, Repository: providers[i], Authorizer: authorizer, Action: in.Action, Intent: func(scopeCommandInput) (auth.Request, error) { return auth.Request{}, nil }}
	}
	command, err := app.NewCommand(app.CommandOptions[scopeCommandInput, *scopeAccess, struct{}]{Resources: resources, Access: access, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestScopeCapabilitiesEnforceAllConditionsBeforeReads(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	queries := countScopeQueries(t, env.db)
	in := scopeCommandInput{Action: "http_list"}
	names := []string{"tree", "tenants"}
	command := scopeCapabilityCommand(t, env.scopeService, in, names, []spec.Spec{spec.All(), spec.In(meta.ByField("ID"))}, []app.IExecutionDescriptorProvider{env.scopeRepo, env.scopeService.catalogs["tenants"]}, func(_ context.Context, input scopeCommandInput, grants []*app.CommandGrant) (*scopeAccess, error) {
		return env.scopeService.bindAccess(input, names, grants)
	}, func(ctx context.Context, _ scopeCommandInput, access *scopeAccess) (struct{}, error) {
		if err := access.check(ctx); err != nil {
			return struct{}{}, err
		}
		_, err := access.list(ctx)
		return struct{}{}, err
	})
	if _, err := command.Execute(env.backgroundCtx, in); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("partial condition=%v", err)
	}
	if queries.Load() != 0 {
		t.Fatal("earlier resource read before later capability condition checked")
	}
}

func TestScopeCapabilitiesEnforceTargetIdentityAndLifetime(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	in := scopeCommandInput{Action: "http_visibility", ScopeCommandInput: ScopeCommandInput{ID: 1}}
	names := []string{"tree", "visibility"}
	var held *scopeAccess
	command := scopeCapabilityCommand(t, env.scopeService, in, names, []spec.Spec{spec.All(), spec.All()}, []app.IExecutionDescriptorProvider{env.scopeRepo, env.scopeService.catalogs["visibility"]}, func(_ context.Context, input scopeCommandInput, grants []*app.CommandGrant) (*scopeAccess, error) {
		return env.scopeService.bindAccess(input, names, grants)
	}, func(ctx context.Context, _ scopeCommandInput, access *scopeAccess) (struct{}, error) {
		held = access
		if _, err := access.visibilityRead.Read(ctx, 2); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("changed visibility target=%v", err)
		}
		other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", IsSystem: true, ActiveScopeID: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := access.visibilityRead.Read(other, 1); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("changed identity=%v", err)
		}
		return struct{}{}, access.check(ctx)
	})
	if _, err := command.Execute(env.backgroundCtx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := held.visibilityRead.Read(env.backgroundCtx, 1); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired capability=%v", err)
	}
}

func TestScopeCapabilityFactoryRejectsDifferentProviderActionAndGrantSet(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	other := setupScopeServiceTest(t)
	defer other.teardown(t)
	in := scopeCommandInput{Action: "http_list"}
	names := []string{"tree", "tenants"}
	command := scopeCapabilityCommand(t, env.scopeService, in, names, []spec.Spec{spec.All(), spec.All()}, []app.IExecutionDescriptorProvider{env.scopeRepo, env.scopeService.catalogs["tenants"]}, func(_ context.Context, input scopeCommandInput, grants []*app.CommandGrant) (*scopeAccess, error) {
		if _, err := other.scopeService.bindAccess(input, names, grants); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("foreign provider=%v", err)
		}
		changed := input
		changed.Action = "http_visibility"
		if _, err := env.scopeService.bindAccess(changed, names, grants); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("wrong action=%v", err)
		}
		if _, err := env.scopeService.bindAccess(input, []string{"tree", "roles"}, grants); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("wrong resource=%v", err)
		}
		if _, err := env.scopeService.bindAccess(input, names, grants[:1]); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("missing grant=%v", err)
		}
		return env.scopeService.bindAccess(input, names, grants)
	}, func(ctx context.Context, _ scopeCommandInput, access *scopeAccess) (struct{}, error) {
		return struct{}{}, access.check(ctx)
	})
	if _, err := command.Execute(env.backgroundCtx, in); err != nil {
		t.Fatal(err)
	}
}

func TestScopeWriterRejectsChangedTargetAndOperationBeforeDatabaseAccess(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	queries := countScopeQueries(t, env.db)
	in := scopeCommandInput{Action: "update", ScopeCommandInput: ScopeCommandInput{ID: 99}}
	names := []string{"tree"}
	var held *scopeAccess
	command := scopeCapabilityCommand(t, env.scopeService, in, names, []spec.Spec{spec.All()}, []app.IExecutionDescriptorProvider{env.scopeRepo}, func(_ context.Context, input scopeCommandInput, grants []*app.CommandGrant) (*scopeAccess, error) {
		return env.scopeService.bindAccess(input, names, grants)
	}, func(ctx context.Context, _ scopeCommandInput, access *scopeAccess) (struct{}, error) {
		held = access
		for _, input := range []scopeTreeInput{
			{Operation: "update", Scope: &iamentity.Scope{}},
			{Operation: "delete", Scope: &iamentity.Scope{}},
		} {
			if _, err := access.writer.Write(ctx, input); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("invalid write=%v", err)
			}
		}
		return struct{}{}, nil
	})
	if _, err := command.Execute(env.backgroundCtx, in); err != nil {
		t.Fatal(err)
	}
	if queries.Load() != 0 {
		t.Fatal("invalid writer accessed database")
	}
	if _, err := held.writer.Write(env.backgroundCtx, scopeTreeInput{}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired writer=%v", err)
	}
}

func TestScopeServiceRequiresEveryActualRepository(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	for _, name := range []string{"tree", "tenants", "roles", "users", "groups"} {
		t.Run(name, func(t *testing.T) {
			for _, nilWrapper := range []bool{false, true} {
				s := &ScopeService{scopeRepo: env.scopeRepo, tenantRepo: env.tenantRepo, roleRepo: env.roleRepo, userRepo: env.userRepo, groupRepo: env.groupRepo}
				switch name {
				case "tree":
					s.scopeRepo = nil
					if nilWrapper {
						s.scopeRepo = &scoperepo.ScopeRepo{}
					}
				case "tenants":
					s.tenantRepo = nil
					if nilWrapper {
						copy := *env.tenantRepo
						copy.Repo = nil
						s.tenantRepo = &copy
					}
				case "roles":
					s.roleRepo = nil
					if nilWrapper {
						copy := *env.roleRepo
						copy.Repo = nil
						s.roleRepo = &copy
					}
				case "users":
					s.userRepo = nil
					if nilWrapper {
						copy := *env.userRepo
						copy.Repo = nil
						s.userRepo = &copy
					}
				case "groups":
					s.groupRepo = nil
					if nilWrapper {
						copy := *env.groupRepo
						copy.Repo = nil
						s.groupRepo = &copy
					}
				}
				if err := s.compileCommands(); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("missing repository=%v", err)
				}
			}
		})
	}
}
