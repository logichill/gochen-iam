package role

import (
	"context"
	"path/filepath"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRoleServiceAddPermission_RejectsScopeMismatch(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "role_scope_test.db")
	t.Setenv("IAM_TENANT_MODE", "tenant")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(
		&iamentity.Scope{},
		&iamentity.Role{},
		&iamentity.User{},
		&iamentity.Group{},
		&iamentity.Tenant{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newRoleTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	roleRepo, err := rolerepo.NewRoleRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}
	userRepo, err := userrepo.NewUserRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	groupRepo, err := grouprepo.NewGroupRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}

	ctx := context.Background()
	ctx, err = ctxx.WithTenantID(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx, err = authz.WithPrincipal(ctx, authz.Principal{
		SubjectID:   1,
		TenantID:    "tenant-a",
		Permissions: []string{"*:*:*"},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	tenantScope := &iamentity.Scope{
		Key:    "tenant:tenant-a",
		Name:   "tenant-a",
		Type:   iamentity.ScopeTypeTenant,
		Path:   "/platform/tenant:tenant-a",
		Depth:  1,
		Status: iamentity.ScopeStatusActive,
	}
	if err := scopeRepo.Create(ctx, tenantScope); err != nil {
		t.Fatalf("create tenant scope: %v", err)
	}
	tenant := &iamentity.Tenant{
		Key:         "tenant-a",
		Name:        "tenant-a",
		Status:      svc.TenantStatusActive,
		RootScopeID: &tenantScope.ID,
	}
	if err := tenantRepo.Create(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	role := &iamentity.Role{
		TenantID:         "tenant-a",
		NamespaceScopeID: tenantScope.ID,
		Code:             "tenant-admin-lite",
		Name:             "tenant-admin-lite",
		Status:           svc.RoleStatusActive,
	}
	if err := roleRepo.Create(ctx, role); err != nil {
		t.Fatalf("create role: %v", err)
	}
	scopeAuthorizer := svc.NewScopeAuthorizer(scopeRepo, tenantRepo)
	authorizer, err := svc.NewIAMAuthorizer(scopeAuthorizer)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	roleService := NewRoleService(
		roleRepo,
		userRepo,
		groupRepo,
		scopeAuthorizer,
		authorizer,
		nil,
	)

	if err := roleService.AddPermission(ctx, role.ID, "api:menu:write"); err == nil {
		t.Fatalf("expected tenant-scoped role to reject platform-only permission")
	}
}
