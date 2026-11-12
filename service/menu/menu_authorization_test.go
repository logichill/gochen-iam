package menu

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	menurepo "gochen-iam/repo/menu"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func menuPrincipal(t *testing.T, subject, scope string, permissions ...string) context.Context {
	t.Helper()
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: subject, ActiveScopeID: 1, Permissions: permissions})
	if err != nil {
		t.Fatal(err)
	}
	return iamauth.BindActiveScopeContext(ctx, 1, scope)
}

func countMenuAccess(t *testing.T, storage *gorm.DB) *atomic.Int64 {
	t.Helper()
	counter := &atomic.Int64{}
	callback := func(*gorm.DB) { counter.Add(1) }
	for _, err := range []error{
		storage.Callback().Query().Before("gorm:query").Register("menu:test:access", callback),
		storage.Callback().Create().Before("gorm:create").Register("menu:test:access", callback),
		storage.Callback().Update().Before("gorm:update").Register("menu:test:access", callback),
		storage.Callback().Delete().Before("gorm:delete").Register("menu:test:access", callback),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return counter
}

func TestMenuConstructionRequiresActualDeclarations(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	for _, repo := range []*menurepo.MenuItemRepo{nil, {}} {
		if _, err := NewMenuService(repo, svc.NewIAMAccess(nil), nil); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("missing repository error=%v", err)
		}
	}
}

func TestMenuRejectsUntrustedAndUnpermittedCallsBeforeDataAccess(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	accesses := countMenuAccess(t, env.db)
	trace, err := contextx.WithUserID(t.Context(), "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), trace, menuPrincipal(t, "7", "platform", "user:api:read")} {
		for action := range env.menuService.commands {
			if action == "my" || action == "http_my" {
				continue
			}
			before := accesses.Load()
			_, err := env.menuService.execute(ctx, action, menuActionInput{ID: 1, Sync: &SyncMenuItemsRequest{Items: []SyncMenuItemRequest{{Code: "denied", Title: "Denied"}}}})
			if !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
				t.Fatalf("%s err=%v accesses=%d", action, err, accesses.Load()-before)
			}
		}
		for _, application := range []*appcrud.Application[*iamentity.MenuItem, int64]{env.menuService.application, env.menuService.httpApplication} {
			for _, invoke := range []func() error{
				func() error { _, err := application.Get(ctx, 1); return err },
				func() error { _, err := application.List(ctx, 0, 0); return err },
				func() error { return application.Create(ctx, &iamentity.MenuItem{Code: "denied", Title: "Denied"}) },
				func() error { return application.Update(ctx, &iamentity.MenuItem{}) },
				func() error { return application.Delete(ctx, 1) },
				func() error { return application.DeleteBulk(ctx, []int64{1, 2}) },
			} {
				before := accesses.Load()
				if err := invoke(); !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
					t.Fatalf("CRUD err=%v accesses=%d", err, accesses.Load()-before)
				}
			}
		}
	}
	for _, ctx := range []context.Context{t.Context(), trace, menuPrincipal(t, "service", "platform")} {
		for _, action := range []string{"my", "http_my"} {
			before := accesses.Load()
			if _, err := env.menuService.execute(ctx, action, menuActionInput{}); !errors.Is(err, errors.Unauthorized) || accesses.Load() != before {
				t.Fatalf("navigation %s err=%v accesses=%d", action, err, accesses.Load()-before)
			}
		}
	}
}

func TestMenuHTTPRequiresExistingManageAndActionPermission(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	accesses := countMenuAccess(t, env.db)
	for _, test := range []struct {
		name, subject, scope  string
		permissions           []string
		system, single, allow bool
	}{
		{"read_only", "7", "platform", []string{"menu:api:read"}, false, false, false},
		{"manage_only", "7", "platform", []string{"menu:api:manage"}, false, false, false},
		{"both", "7", "platform", []string{"menu:api:manage", "menu:api:read"}, false, false, true},
		{"wildcard", "7", "platform", []string{"menu:api:*"}, false, false, true},
		{"tenant_wildcard", "7", "tenant", []string{"menu:api:*"}, false, false, false},
		{"single_platform", "7", "platform", []string{"menu:api:*"}, false, true, true},
		{"single_tenant", "7", "tenant", []string{"menu:api:*"}, false, true, false},
		{"system_platform", "7", "platform", nil, true, false, true},
		{"system_tenant", "7", "tenant", nil, true, false, false},
		{"single_system_tenant", "7", "tenant", nil, true, true, true},
		{"system_no_user", "", "platform", nil, true, false, false},
		{"system_text_user", "worker", "platform", nil, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := tenant.ModeTenant
			if test.single {
				mode = tenant.ModeSingle
			}
			ctx, err := hostauthz.WithPrincipal(tenant.WithPolicy(t.Context(), tenant.Policy{Mode: mode}), hostauthz.Principal{SubjectID: test.subject, Permissions: test.permissions, IsSystem: test.system, ActiveScopeID: 1})
			if err != nil {
				t.Fatal(err)
			}
			ctx = iamauth.BindActiveScopeContext(ctx, 1, test.scope)
			before := accesses.Load()
			_, err = env.menuService.HTTPApplication().List(ctx, 0, 0)
			if test.allow {
				if err != nil || accesses.Load() <= before {
					t.Fatalf("allowed err=%v accesses=%d", err, accesses.Load()-before)
				}
			} else if err == nil || accesses.Load() != before {
				t.Fatalf("denied err=%v accesses=%d", err, accesses.Load()-before)
			}
		})
	}
	for _, action := range []string{"sync", "restore", "purge", "publish"} {
		permission := "menu:api:write"
		if action == "publish" {
			permission = "menu:api:publish"
		}
		for _, permissions := range [][]string{{permission}, {"menu:api:manage"}, {"menu:api:manage", permission}} {
			ctx := menuPrincipal(t, "7", "platform", permissions...)
			before := accesses.Load()
			_, err := env.menuService.execute(ctx, "http_"+action, menuActionInput{ID: 99, Sync: &SyncMenuItemsRequest{Items: []SyncMenuItemRequest{{Code: "allowed", Title: "Allowed"}}}})
			if len(permissions) == 1 {
				if !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
					t.Fatalf("%s err=%v accesses=%d", action, err, accesses.Load()-before)
				}
			} else if errors.Is(err, errors.Forbidden) || accesses.Load() <= before {
				t.Fatalf("%s allowed err=%v accesses=%d", action, err, accesses.Load()-before)
			}
		}
	}
}

func TestMenuNavigationUsesTheSameTrustedUsersPermissions(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	root := env.createMenuItem(t, &CreateMenuItemRequest{Code: "root", Title: "Root", Type: "group", Published: true, AllOfPermissions: []string{"user:api:write"}})
	env.createMenuItem(t, &CreateMenuItemRequest{Code: "child", Title: "Child", ParentID: &root.ID, Published: true, AnyOfPermissions: []string{"user:api:read", "group:api:read"}})
	for _, item := range []CreateMenuItemRequest{
		{Code: "hidden", Title: "Hidden", Published: true, Hidden: true},
		{Code: "disabled", Title: "Disabled", Published: true, Disabled: true},
		{Code: "draft", Title: "Draft"},
		{Code: "requires_all", Title: "All", Published: true, AllOfPermissions: []string{"user:api:read", "group:api:read"}},
	} {
		env.createMenuItem(t, &item)
	}
	ctx := menuPrincipal(t, "7", "tenant", "user:api:read")
	for _, action := range []string{"my", "http_my"} {
		out, err := env.menuService.execute(ctx, action, menuActionInput{})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Tree) != 1 || out.Tree[0].Code != "root" || len(out.Tree[0].Children) != 1 || out.Tree[0].Children[0].Code != "child" {
			t.Fatalf("%s tree=%+v", action, out.Tree)
		}
	}
	withoutPermissions := menuPrincipal(t, "8", "tenant")
	if tree, err := env.menuService.MyMenuTree(withoutPermissions); err != nil || len(tree) != 0 {
		t.Fatalf("different user inherited permissions: tree=%+v err=%v", tree, err)
	}
}

type menuTestCondition struct{ condition spec.Spec }

func (menuTestCondition) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByField("ID")}}
}
func (p menuTestCondition) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: true, Spec: p.condition}, nil
}

func menuTestCommand(t *testing.T, s *MenuService, action string, conditions []spec.Spec, providers []app.IExecutionDescriptorProvider, run func(context.Context, menuActionInput, menuActionAccess) (struct{}, error)) *app.Command[menuActionInput, menuActionAccess, struct{}] {
	t.Helper()
	names, kinds := []string{"menu"}, []auth.Kind{auth.KindUpdate}
	if action == "sync" {
		names, kinds = append(names, "menu_creates", "menu_relations"), append(kinds, auth.KindCreate, auth.KindRead)
	}
	resources := make([]app.CommandResource[menuActionInput], len(names))
	for i, name := range names {
		resourceAction := action
		if name == "menu_creates" {
			resourceAction += "_creates"
		}
		if name == "menu_relations" {
			resourceAction += "_relations"
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: svc.MenuResourceKind, Actions: []auth.Action{{Name: resourceAction, Kind: kinds[i], Permission: "menu:api:write"}}}, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "test.menu", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{menuTestCondition{conditions[i]}}}}}, auth.CompileOptions{Metadata: providers[i].ExecutionDescriptor().Metadata(), Checker: hostauthz.NewActionChecker()})
		if err != nil {
			t.Fatal(err)
		}
		resources[i] = app.CommandResource[menuActionInput]{Name: name, Repository: providers[i], Authorizer: authorizer, Action: resourceAction, Intent: func(in menuActionInput) (auth.Request, error) {
			if action == "sync" {
				return auth.Request{}, nil
			}
			return auth.Request{IDs: []string{"1"}}, nil
		}}
	}
	command, err := app.NewCommand(app.CommandOptions[menuActionInput, menuActionAccess, struct{}]{Resources: resources, Access: func(_ context.Context, _ menuActionInput, grants []*app.CommandGrant) (menuActionAccess, error) {
		return s.bindMenuAccess(action, grants)
	}, Handler: run})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestMenuSyncAuthorizesAllResourcesBeforeWrites(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	accesses := countMenuAccess(t, env.db)
	for rejected := 0; rejected < 3; rejected++ {
		conditions := []spec.Spec{spec.All(), spec.All(), spec.All()}
		conditions[rejected] = spec.In(meta.ByField("ID"))
		command := menuTestCommand(t, env.menuService, "sync", conditions, []app.IExecutionDescriptorProvider{env.menuRepo, env.menuRepo, env.menuRepo}, func(ctx context.Context, _ menuActionInput, a menuActionAccess) (struct{}, error) {
			_, err := a.lookup.Read(ctx, menuLookupInput{Operation: "check"})
			if err == nil {
				err = a.creates.Create(ctx, &iamentity.MenuItem{Code: "denied", Title: "Denied"})
			}
			return struct{}{}, err
		})
		before := accesses.Load()
		if _, err := command.Execute(env.backgroundCtx, menuActionInput{}); !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
			t.Fatalf("resource %d err=%v accesses=%d", rejected, err, accesses.Load()-before)
		}
	}
}

func TestMenuCapabilitiesBindProviderTargetIdentityAndLifetime(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	item := env.createMenuItem(t, &CreateMenuItemRequest{Code: "target", Title: "Target"})
	if item.ID != 1 {
		t.Fatalf("unexpected fixture ID=%d", item.ID)
	}
	accesses := countMenuAccess(t, env.db)
	var retained menuActionAccess
	command := menuTestCommand(t, env.menuService, "restore", []spec.Spec{spec.All()}, []app.IExecutionDescriptorProvider{env.menuRepo}, func(ctx context.Context, _ menuActionInput, a menuActionAccess) (struct{}, error) {
		retained = a
		for _, invoke := range []func() error{
			func() error { _, err := a.menus.Get(ctx, 2); return err },
			func() error { _, err := a.menus.Get(menuPrincipal(t, "8", "platform", "menu:api:*"), 1); return err },
			func() error { return a.menus.Create(ctx, &iamentity.MenuItem{Code: "outside", Title: "Outside"}) },
		} {
			before := accesses.Load()
			if err := invoke(); !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
				t.Fatalf("capability err=%v accesses=%d", err, accesses.Load()-before)
			}
		}
		return struct{}{}, nil
	})
	if _, err := command.Execute(env.backgroundCtx, menuActionInput{ID: 1}); err != nil {
		t.Fatal(err)
	}
	before := accesses.Load()
	if _, err := retained.menus.Get(env.backgroundCtx, 1); !errors.Is(err, errors.FailedPrecondition) || accesses.Load() != before {
		t.Fatalf("expired capability err=%v", err)
	}
	other := setupMenuServiceTest(t)
	defer other.teardown(t)
	wrongProvider := menuTestCommand(t, env.menuService, "restore", []spec.Spec{spec.All()}, []app.IExecutionDescriptorProvider{other.menuRepo}, func(context.Context, menuActionInput, menuActionAccess) (struct{}, error) {
		t.Fatal("wrong provider entered handler")
		return struct{}{}, nil
	})
	if _, err := wrongProvider.Execute(env.backgroundCtx, menuActionInput{ID: 1}); !errors.Is(err, errors.InvalidInput) || accesses.Load() != before {
		t.Fatalf("wrong provider err=%v", err)
	}
}

func TestMenuSyncRollsBackCreateUpdateAndParentFailures(t *testing.T) {
	for _, failure := range []string{"create", "update", "parent"} {
		t.Run(failure, func(t *testing.T) {
			env := setupMenuServiceTest(t)
			defer env.teardown(t)
			input := &SyncMenuItemsRequest{Upsert: true, Items: []SyncMenuItemRequest{{Code: "first", Title: "First"}, {Code: "second", Title: "Second"}}}
			switch failure {
			case "create":
				if err := env.db.Exec(`CREATE TRIGGER fail_menu_create BEFORE INSERT ON menu_items WHEN NEW.code = 'second' BEGIN SELECT RAISE(ABORT, 'injected create failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "update":
				env.createMenuItem(t, &CreateMenuItemRequest{Code: "second", Title: "Before"})
				if err := env.db.Exec(`CREATE TRIGGER fail_menu_update BEFORE UPDATE ON menu_items WHEN NEW.code = 'second' BEGIN SELECT RAISE(ABORT, 'injected update failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "parent":
				parent := env.createMenuItem(t, &CreateMenuItemRequest{Code: "removed", Title: "Removed"})
				if err := env.menuService.DeleteMenuItem(env.backgroundCtx, parent.ID); err != nil {
					t.Fatal(err)
				}
				input.Items = []SyncMenuItemRequest{{Code: "first", Title: "First"}, {Code: "second", Title: "Second", ParentCode: "removed"}, {Code: "removed", Title: "Removed"}}
			}
			if _, err := env.menuService.SyncMenuItems(env.backgroundCtx, input); err == nil {
				t.Fatal("expected transaction failure")
			}
			var count int64
			if err := env.db.Model(&iamentity.MenuItem{}).Where("code IN ?", []string{"first", "second"}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if failure == "update" {
				want = 1
				var second iamentity.MenuItem
				if err := env.db.Where("code = ?", "second").First(&second).Error; err != nil {
					t.Fatal(err)
				}
				if second.Title != "Before" || second.Version != 0 {
					t.Fatalf("update escaped rollback: %+v", second)
				}
			}
			if count != want {
				t.Fatalf("create escaped rollback: count=%d want=%d", count, want)
			}
		})
	}
}

func TestMenuSyncAndRestorePreserveLifecycleSemantics(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	input := &SyncMenuItemsRequest{Upsert: true, SyncPermissions: true, Items: []SyncMenuItemRequest{{Code: "child", Title: "Child", ParentCode: "root", Published: true, AnyOfPermissions: []string{"user:api:read"}}, {Code: "root", Title: "Root", Type: "group", Published: true}}}
	out, err := env.menuService.SyncMenuItems(env.backgroundCtx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Created, []string{"child", "root"}) {
		t.Fatalf("created=%+v", out)
	}
	root, err := env.menuRepo.FindByCode(env.backgroundCtx, "root")
	if err != nil {
		t.Fatal(err)
	}
	child, err := env.menuRepo.FindByCode(env.backgroundCtx, "child")
	if err != nil {
		t.Fatal(err)
	}
	if child.ParentID == nil || *child.ParentID != root.ID || child.Version != 1 {
		t.Fatalf("parent/version=%+v", child)
	}
	input.Items[0].Title = "Changed"
	input.Items[0].AnyOfPermissions = []string{"group:api:read"}
	input.Upsert = false
	out, err = env.menuService.SyncMenuItems(env.backgroundCtx, input)
	if err != nil {
		t.Fatal(err)
	}
	child, err = env.menuRepo.Get(env.backgroundCtx, child.ID, spec.All())
	if err != nil {
		t.Fatal(err)
	}
	if child.Title != "Child" || !reflect.DeepEqual([]string(child.AnyOfPermissions), []string{"group:api:read"}) || !reflect.DeepEqual(out.Updated, []string{"child"}) {
		t.Fatalf("upsert/permissions: item=%+v result=%+v", child, out)
	}
	if _, err := env.menuService.PublishMenuItem(env.backgroundCtx, child.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := env.menuService.DeleteMenuItem(env.backgroundCtx, child.ID); err != nil {
		t.Fatal(err)
	}
	out, err = env.menuService.SyncMenuItems(env.backgroundCtx, input)
	if err != nil || len(out.Skipped) != 2 {
		t.Fatalf("deleted skip=%+v err=%v", out, err)
	}
	restored, err := env.menuService.RestoreMenuItem(env.backgroundCtx, child.ID)
	if err != nil || restored.DeletedAt != nil {
		t.Fatalf("restore=%+v err=%v", restored, err)
	}
	again, err := env.menuService.RestoreMenuItem(env.backgroundCtx, child.ID)
	if err != nil || again.Version != restored.Version {
		t.Fatalf("restore idempotence=%+v err=%v", again, err)
	}
	if err := env.menuService.PurgeMenuItem(env.backgroundCtx, child.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.menuRepo.GetWithDeleted(env.backgroundCtx, child.ID, spec.All()); !errors.Is(err, errors.NotFound) {
		t.Fatalf("purge error=%v", err)
	}
}

func TestMenuFullListPreservesUnboundedServiceQuery(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	items := make([]*iamentity.MenuItem, 1001)
	for i := range items {
		items[i] = &iamentity.MenuItem{Code: fmt.Sprintf("item-%d", i), Title: "Item", Type: "page"}
		items[i].ID = int64(i + 1)
	}
	if err := env.db.CreateInBatches(items, 100).Error; err != nil {
		t.Fatal(err)
	}
	out, err := env.menuService.ListMenuItems(env.backgroundCtx)
	if err != nil || len(out) != len(items) {
		t.Fatalf("list size=%d want=%d err=%v", len(out), len(items), err)
	}
}

func TestMenuRelationshipReaderRejectsPartialConditionsAndOtherOperations(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)
	accesses := countMenuAccess(t, env.db)
	for _, condition := range []spec.Spec{spec.Eq(meta.ByField("ID"), int64(1)), spec.All()} {
		var retained menuActionAccess
		command := menuTestCommand(t, env.menuService, "sync", []spec.Spec{spec.All(), spec.All(), condition}, []app.IExecutionDescriptorProvider{env.menuRepo, env.menuRepo, env.menuRepo}, func(ctx context.Context, _ menuActionInput, a menuActionAccess) (struct{}, error) {
			retained = a
			if !condition.IsAll() {
				_, err := a.lookup.Read(ctx, menuLookupInput{Operation: "check"})
				return struct{}{}, err
			}
			for _, op := range []string{"all", "published", "unknown"} {
				if _, err := a.lookup.Read(ctx, menuLookupInput{Operation: op}); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("unexpected %s lookup err=%v", op, err)
				}
			}
			if _, err := a.lookup.Read(menuPrincipal(t, "8", "platform", "menu:api:*"), menuLookupInput{Operation: "check"}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity lookup err=%v", err)
			}
			return struct{}{}, nil
		})
		before := accesses.Load()
		_, err := command.Execute(env.backgroundCtx, menuActionInput{})
		if condition.IsAll() && err != nil || !condition.IsAll() && !errors.Is(err, errors.Forbidden) || accesses.Load() != before {
			t.Fatalf("condition=%s err=%v accesses=%d", condition.Canonical(), err, accesses.Load()-before)
		}
		if _, err := retained.lookup.Read(env.backgroundCtx, menuLookupInput{Operation: "check"}); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("expired lookup err=%v", err)
		}
	}
}
