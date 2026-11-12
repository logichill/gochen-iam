package scope

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/errors"
)

func TestCreateTenantRollsBackWhenRootScopeInsertFails(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.cancelFunc()
	authorizer := svc.NewIAMAccess(env.scopeAuthorizer)
	service, err := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec(`CREATE TRIGGER fail_tenant_scope BEFORE INSERT ON scopes
		WHEN NEW.type = 'tenant' BEGIN SELECT RAISE(ABORT, 'injected scope failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateTenant(env.backgroundCtx, &svc.CreateTenantRequest{Key: "atomic-tenant", Name: "Atomic Tenant"}); err == nil {
		t.Fatal("expected root scope insert failure")
	}
	var count int64
	if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", "atomic-tenant").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed create left %d tenants behind", count)
	}
}

func TestRepairTenantRootScopeRollsBackWhenTenantUpdateFails(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.cancelFunc()
	tenant := &iamentity.Tenant{Key: "repair-atomic", Name: "Repair Atomic", Status: svc.TenantStatusInactive}
	if err := env.db.Create(tenant).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec(`CREATE TRIGGER fail_tenant_scope_link BEFORE UPDATE ON tenants
		WHEN NEW.root_scope_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected tenant failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	service, err := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, svc.NewIAMAccess(env.scopeAuthorizer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RepairTenantRootScope(env.backgroundCtx, tenant.ID); err == nil {
		t.Fatal("expected tenant update failure")
	}
	var count int64
	if err := env.db.Model(&iamentity.Scope{}).Where("key = ?", "tenant:repair-atomic").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed repair left %d scopes behind", count)
	}
}

func TestTenantCommandsLifecycleReturnsPersistedVersion(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	service, err := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, svc.NewIAMAccess(env.scopeAuthorizer))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"tenant:api:*"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, iamentity.ScopeTypePlatform)
	created, err := service.CreateTenant(ctx, &svc.CreateTenantRequest{Key: "lifecycle", Name: "Lifecycle", Description: "Original"})
	if err != nil {
		t.Fatal(err)
	}
	var persisted iamentity.Tenant
	if err := env.db.First(&persisted, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if created.RootScopeID == nil || persisted.RootScopeID == nil || *created.RootScopeID != *persisted.RootScopeID || created.Version != persisted.Version {
		t.Fatalf("create returned stale root/version: %+v, persisted %+v", created, persisted)
	}
	updated, err := service.UpdateTenant(ctx, created.ID, &svc.UpdateTenantRequest{Name: "Updated", Description: "Changed"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || updated.Description != "Changed" || updated.Version <= created.Version {
		t.Fatalf("update=%+v", updated)
	}
	for _, transition := range []struct{ action, status string }{{"activate", svc.TenantStatusActive}, {"deactivate", svc.TenantStatusInactive}} {
		if _, err := service.ExecuteHTTP(ctx, transition.action, tenantsvc.TenantCommandInput{ID: created.ID}); err != nil {
			t.Fatal(err)
		}
		found, err := service.Tenant(ctx, created.ID)
		if err != nil || found.Status != transition.status {
			t.Fatalf("%s: %+v %v", transition.action, found, err)
		}
	}
	root, err := service.RepairTenantRootScope(ctx, created.ID)
	if err != nil || root.Name != "Updated" || root.Description != "Changed" {
		t.Fatalf("repair=%+v %v", root, err)
	}
	if _, err := service.CreateTenant(ctx, &svc.CreateTenantRequest{Key: "lifecycle", Name: "Duplicate"}); !errors.Is(err, errors.Validation) {
		t.Fatalf("duplicate=%v", err)
	}
	if _, err := service.Tenant(ctx, 9999); !errors.Is(err, errors.NotFound) {
		t.Fatalf("missing=%v", err)
	}
	items, err := service.ListTenants(ctx)
	if err != nil || len(items) != 1 || items[0].ID != created.ID {
		t.Fatalf("list=%+v %v", items, err)
	}
}

func TestTenantListIncludesAllPagesAndFiltersDeletedRows(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)
	service, err := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, svc.NewIAMAccess(env.scopeAuthorizer))
	if err != nil {
		t.Fatal(err)
	}
	items := make([]iamentity.Tenant, 1002)
	for i := range items {
		items[i] = iamentity.Tenant{Key: fmt.Sprintf("page-%04d", i), Name: "Paged", Status: svc.TenantStatusInactive}
		items[i].ID = int64(i + 10)
	}
	now := time.Now()
	items[500].DeletedAt = &now
	if err := env.db.CreateInBatches(items, 100).Error; err != nil {
		t.Fatal(err)
	}
	result, err := service.ListTenants(env.backgroundCtx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1001 {
		t.Fatalf("list returned %d, want 1001", len(result))
	}
	for i, item := range result {
		if item.DeletedAt != nil || i > 0 && item.ID <= result[i-1].ID {
			t.Fatal("list pagination lost sorting or soft-delete filtering")
		}
	}
}

func TestTenantRootCommandsRollBackAllResourcesOnEveryFailure(t *testing.T) {
	for _, action := range []string{"create", "repair", "http_repair"} {
		for _, failure := range []struct{ name, trigger string }{
			{"root", `CREATE TRIGGER tenant_failure BEFORE INSERT ON scopes WHEN NEW.type = 'tenant' BEGIN SELECT RAISE(ABORT, 'injected root failure'); END`},
			{"visibility", `CREATE TRIGGER tenant_failure BEFORE INSERT ON scope_visibility_map BEGIN SELECT RAISE(ABORT, 'injected visibility failure'); END`},
			{"link", `CREATE TRIGGER tenant_failure BEFORE UPDATE ON tenants WHEN NEW.root_scope_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected link failure'); END`},
		} {
			t.Run(action+"/"+failure.name, func(t *testing.T) {
				env := setupScopeServiceTest(t)
				defer env.teardown(t)
				service, err := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, svc.NewIAMAccess(env.scopeAuthorizer))
				if err != nil {
					t.Fatal(err)
				}
				tenant := &iamentity.Tenant{Key: "atomic-all", Name: "Atomic", Status: svc.TenantStatusInactive}
				if action != "create" {
					if err := env.db.Create(tenant).Error; err != nil {
						t.Fatal(err)
					}
				}
				var before []*iamentity.ScopeVisibility
				if err := env.db.Order("viewer_scope_id, target_scope_id").Find(&before).Error; err != nil {
					t.Fatal(err)
				}
				if err := env.db.Exec(failure.trigger).Error; err != nil {
					t.Fatal(err)
				}
				var operation func(context.Context) error
				switch action {
				case "create":
					operation = func(ctx context.Context) error {
						_, err := service.CreateTenant(ctx, &svc.CreateTenantRequest{Key: tenant.Key, Name: tenant.Name})
						return err
					}
				case "repair":
					operation = func(ctx context.Context) error { _, err := service.RepairTenantRootScope(ctx, tenant.ID); return err }
				default:
					operation = func(ctx context.Context) error {
						_, err := service.ExecuteHTTP(ctx, "repair", tenantsvc.TenantCommandInput{ID: tenant.ID})
						return err
					}
				}
				if err := operation(env.backgroundCtx); err == nil {
					t.Fatal("expected injected failure")
				}
				var count int64
				if err := env.db.Model(&iamentity.Scope{}).Where("key = ?", "tenant:atomic-all").Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("rollback left %d tenant roots", count)
				}
				if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", tenant.Key).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				want := int64(1)
				if action == "create" {
					want = 0
				}
				if count != want {
					t.Fatalf("rollback tenant count=%d, want %d", count, want)
				}
				if action != "create" {
					var unchanged iamentity.Tenant
					if err := env.db.First(&unchanged, tenant.ID).Error; err != nil {
						t.Fatal(err)
					}
					if unchanged.RootScopeID != nil || unchanged.Version != tenant.Version {
						t.Fatal("failed repair changed tenant root/version")
					}
				}
				var after []*iamentity.ScopeVisibility
				if err := env.db.Order("viewer_scope_id, target_scope_id").Find(&after).Error; err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed command changed visibility graph")
				}
			})
		}
	}
}
