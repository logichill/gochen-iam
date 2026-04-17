package service

import (
	"context"
	"path/filepath"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	"gochen-iam/tenant"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/domain/crud"
	"gochen/errorx"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeShortCircuitsScopeLookup(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:read")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", ""); err != nil {
		t.Fatalf("RequirePermissionInTenant: %v", err)
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeRejectsMismatchedTenant(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:read")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", "tenant-b"); err == nil {
		t.Fatalf("expected mismatched tenant to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_FixedModeStillRequiresPermission(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	reqCtx := withPermissions(t, newTenantGuardRequestContext(t, "ignored"), "api:role:list")
	authorizer := NewScopeAuthorizer(nil, nil)

	if err := authorizer.RequirePermissionInTenant(reqCtx, "api:role:read", ""); err == nil {
		t.Fatalf("expected missing permission to be rejected")
	}
}

func TestScopeAuthorizerRequirePermissionInTenant_UsesPrincipalOutsideHTTP(t *testing.T) {
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeSingle))
	t.Setenv(tenant.EnvSingleTenantID, "single-tenant")

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		Permissions: []string{"api:role:read"},
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	authorizer := NewScopeAuthorizer(nil, nil)
	if err := authorizer.RequirePermissionInTenant(ctx, "api:role:read", ""); err != nil {
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
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	ctx := context.Background()
	ctx, err = authz.WithPrincipal(ctx, authz.Principal{
		SubjectID:     7,
		Permissions:   []string{"api:role:read"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = ctxx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iamentity.ScopeTypePlatform))
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{
		ActiveScopeID:   1,
		VisibleScopeIDs: []int64{1, 2, 3},
		Mode:            authz.ScopeModeManagedScopes,
	})
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
	if err := authorizer.RequirePermissionInTenant(ctx, "api:role:read", "tenant-b"); err != nil {
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
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter)
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
	ctx, err = authz.WithPrincipal(ctx, authz.Principal{
		SubjectID:     7,
		Permissions:   []string{"api:role:read"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = ctxx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iamentity.ScopeTypePlatform))

	authorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)
	err = authorizer.RequirePermissionInTenant(ctx, "api:role:read", "tenant-b")
	if !errorx.Is(err, errorx.Internal) {
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

func scopeInt64Ptr(v int64) *int64 {
	return &v
}
