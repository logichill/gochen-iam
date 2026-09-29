package service

import (
	"context"
	"gochen/testkit"
	"path/filepath"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/crud"
	"gochen/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeShortCircuitsScopeLookup(t *testing.T) {
	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "role:api:read")
	reqCtx = reqCtx.WithContext(tenant.WithPolicy(reqCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "single-tenant"}))
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "role:api:read", ""); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeRejectsMismatchedTenant(t *testing.T) {
	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "role:api:read")
	reqCtx = reqCtx.WithContext(tenant.WithPolicy(reqCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "single-tenant"}))
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "role:api:read", "tenant-b"); err == nil {
		t.Fatalf("expected mismatched tenant to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeStillRequiresPermission(t *testing.T) {
	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "role:api:list")
	reqCtx = reqCtx.WithContext(tenant.WithPolicy(reqCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "single-tenant"}))
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "role:api:read", ""); err == nil {
		t.Fatalf("expected missing permission to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_UsesPrincipalOutsideHTTP(t *testing.T) {
	ctx, err := auth.WithPrincipal(tenant.WithPolicy(context.Background(), tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "single-tenant"}), auth.Principal{
		Permissions: []string{"role:api:read"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	authorizer := NewScopeAuthorizer(nil, nil)
	if err := authorizer.RequirePermissionInTenant(ctx, "role:api:read", ""); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_AllowsPlatformCrossTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "scope_authorizer_cross_tenant.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}, &iamentity.Tenant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeAuthorizerTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	ctx := context.Background()
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     7,
		Permissions:   []string{"role:api:read"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iamentity.ScopeTypePlatform))
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1, 2, 3))
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	platformScope := &iamentity.Scope{
		Entity: crud.Entity[int64]{ID: 1},
		Key:    "platform",
		Name:   "Platform",
		Type:   iamentity.ScopeTypePlatform,
		Path:   "/platform/",
		Depth:  0,
		Status: iamentity.ScopeStatusActive,
	}
	tenantAScope := &iamentity.Scope{
		Entity:   crud.Entity[int64]{ID: 2},
		Key:      "tenant:tenant-a",
		Name:     "Tenant A",
		Type:     iamentity.ScopeTypeTenant,
		ParentID: scopeInt64Ptr(1),
		Path:     "/platform/tenant:tenant-a/",
		Depth:    1,
		Status:   iamentity.ScopeStatusActive,
	}
	tenantBScope := &iamentity.Scope{
		Entity:   crud.Entity[int64]{ID: 3},
		Key:      "tenant:tenant-b",
		Name:     "Tenant B",
		Type:     iamentity.ScopeTypeTenant,
		ParentID: scopeInt64Ptr(1),
		Path:     "/platform/tenant:tenant-b/",
		Depth:    1,
		Status:   iamentity.ScopeStatusActive,
	}
	for _, scope := range []*iamentity.Scope{platformScope, tenantAScope, tenantBScope} {
		if err := scopeRepo.Create(context.Background(), scope); err != nil {
			t.Fatalf("create scope %s: %v", scope.Key, err)
		}
	}
	for _, tenantRow := range []*iamentity.Tenant{
		{Entity: crud.Entity[int64]{ID: 1}, Key: "tenant-a", Name: "Tenant A", Status: TenantStatusActive, RootScopeID: &tenantAScope.ID},
		{Entity: crud.Entity[int64]{ID: 2}, Key: "tenant-b", Name: "Tenant B", Status: TenantStatusActive, RootScopeID: &tenantBScope.ID},
	} {
		if err := tenantRepo.Create(context.Background(), tenantRow); err != nil {
			t.Fatalf("create tenant %s: %v", tenantRow.Key, err)
		}
	}
	if err := scopeRepo.RebuildVisibilityMap(context.Background()); err != nil {
		t.Fatalf("RebuildVisibilityMap: %v", err)
	}

	authorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)
	if err := authorizer.RequirePermissionInTenant(ctx, "role:api:read", "tenant-b"); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_DoesNotHealMissingTenantRootScope(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "scope_authorizer_missing_root_scope.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}, &iamentity.Tenant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeAuthorizerTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	if err := tenantRepo.Create(context.Background(), &iamentity.Tenant{
		Entity: crud.Entity[int64]{ID: 1},
		Key:    "tenant-b",
		Name:   "Tenant B",
		Status: TenantStatusActive,
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	ctx := context.Background()
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     7,
		Permissions:   []string{"role:api:read"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iamentity.ScopeTypePlatform))

	authorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)
	err = authorizer.RequirePermissionInTenant(ctx, "role:api:read", "tenant-b")
	if !errors.Is(err, errors.Internal) {
		t.Fatalf("RequirePermissionInTenant error = %v, want INTERNAL_ERROR", err)
	}

	var scopeCount int64
	if err := db.Model(&iamentity.Scope{}).Count(&scopeCount).Error; err != nil {
		t.Fatalf("count scopes: %v", err)
	}
	if scopeCount != 0 {
		t.Fatalf("scope count = %d, want 0", scopeCount)
	}
}

func TestScopeAuthorizerTenantRootScopeHealth_MissingAndInconsistent(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "scope_authorizer_root_scope_health.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}, &iamentity.Tenant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeAuthorizerTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	brokenScope := &iamentity.Scope{
		Entity: crud.Entity[int64]{ID: 9},
		Key:    "custom-broken",
		Name:   "Broken Scope",
		Type:   "custom",
		Path:   "/custom-broken/",
		Depth:  0,
		Status: iamentity.ScopeStatusActive,
	}
	if err := scopeRepo.Create(context.Background(), brokenScope); err != nil {
		t.Fatalf("create broken scope: %v", err)
	}

	authorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)

	missingHealth, err := authorizer.TenantRootScopeHealth(context.Background(), &iamentity.Tenant{
		Key:  "tenant-missing",
		Name: "Tenant Missing",
	})
	if err != nil {
		t.Fatalf("TenantRootScopeHealth missing: %v", err)
	}
	if missingHealth.Status != tenantRootScopeStatusMissing || !missingHealth.CanRepair {
		t.Fatalf("unexpected missing health: %+v", missingHealth)
	}

	inconsistentHealth, err := authorizer.TenantRootScopeHealth(context.Background(), &iamentity.Tenant{
		Key:         "tenant-bad",
		Name:        "Tenant Bad",
		RootScopeID: &brokenScope.ID,
	})
	if err != nil {
		t.Fatalf("TenantRootScopeHealth inconsistent: %v", err)
	}
	if inconsistentHealth.Status != tenantRootScopeStatusInconsistent || !inconsistentHealth.CanRepair {
		t.Fatalf("unexpected inconsistent health: %+v", inconsistentHealth)
	}
}

func TestScopeAuthorizerEnsureTenantRootScope_RepairsDriftedExistingScope(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "scope_authorizer_repair_existing_scope.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}, &iamentity.Tenant{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeAuthorizerTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	authorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)
	platformScope, err := authorizer.EnsurePlatformScope(context.Background())
	if err != nil {
		t.Fatalf("EnsurePlatformScope: %v", err)
	}

	driftedScope := &iamentity.Scope{
		Entity:      crud.Entity[int64]{ID: 20},
		Key:         "tenant:tenant-a",
		Name:        "Old Name",
		Type:        "custom",
		ParentID:    nil,
		Path:        "/tenant:tenant-a/",
		Depth:       0,
		Description: "old description",
		Status:      iamentity.ScopeStatusInactive,
	}
	if err := scopeRepo.Create(context.Background(), driftedScope); err != nil {
		t.Fatalf("create drifted scope: %v", err)
	}

	tenantEntity := &iamentity.Tenant{
		Entity:      crud.Entity[int64]{ID: 1},
		Key:         "tenant-a",
		Name:        "Tenant A",
		Description: "Tenant A Desc",
		Status:      TenantStatusActive,
		RootScopeID: &driftedScope.ID,
	}
	if err := tenantRepo.Create(context.Background(), tenantEntity); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	repairedScope, err := authorizer.EnsureTenantRootScope(context.Background(), tenantEntity)
	if err != nil {
		t.Fatalf("EnsureTenantRootScope: %v", err)
	}
	if repairedScope.ID != driftedScope.ID {
		t.Fatalf("expected repaired scope id %d, got %d", driftedScope.ID, repairedScope.ID)
	}
	if repairedScope.Type != iamentity.ScopeTypeTenant {
		t.Fatalf("expected repaired scope type tenant, got %s", repairedScope.Type)
	}
	if repairedScope.ParentID == nil || *repairedScope.ParentID != platformScope.ID {
		t.Fatalf("expected repaired scope parent %d, got %v", platformScope.ID, repairedScope.ParentID)
	}
	expectedPath := iamentity.ScopePathFor(platformScope.Path, "tenant:tenant-a")
	if repairedScope.Path != expectedPath {
		t.Fatalf("expected repaired path %s, got %s", expectedPath, repairedScope.Path)
	}
	if repairedScope.Status != iamentity.ScopeStatusActive {
		t.Fatalf("expected repaired scope status active, got %s", repairedScope.Status)
	}
	if repairedScope.Name != tenantEntity.Name || repairedScope.Description != tenantEntity.Description {
		t.Fatalf("expected repaired scope metadata to follow tenant, got %+v", repairedScope)
	}

	health, err := authorizer.TenantRootScopeHealth(context.Background(), tenantEntity)
	if err != nil {
		t.Fatalf("TenantRootScopeHealth: %v", err)
	}
	if health.Status != tenantRootScopeStatusHealthy || health.CanRepair {
		t.Fatalf("expected healthy root scope after repair, got %+v", health)
	}
}

func scopeInt64Ptr(v int64) *int64 {
	return &v
}
