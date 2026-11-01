package scope

import (
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
)

func TestCreateTenantRollsBackWhenRootScopeInsertFails(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.cancelFunc()
	authorizer := svc.NewIAMAuthorizer(env.scopeAuthorizer)
	service := tenantsvc.NewTenantService(env.tenantRepo, env.scopeAuthorizer, authorizer)
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
	if _, err := env.scopeAuthorizer.EnsureTenantRootScope(env.backgroundCtx, tenant); err == nil {
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
