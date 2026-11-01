package role

import (
	"context"
	"gochen/gen"
	"gochen/observe/logging"
	"gochen/testkit"
	"path/filepath"
	"slices"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-iam/persistence/gormsetup"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	auth "gochen-runtime/host/authz"
	"gochen/contextx"
	"gochen/domain/spec"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRoleServiceCheckPermissionIncludesGroupDefaultRoles(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "role_permission_check_test.db")

	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)
	t.Setenv("IAM_TENANT_MODE", "tenant")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := gormsetup.SetupJoinTables(db); err != nil {
		t.Fatalf("setup join tables: %v", err)
	}
	if err := db.AutoMigrate(
		&iamentity.Scope{},
		&iamentity.ScopeVisibility{},
		&iamentity.UserRoleBinding{},
		&iamentity.Group{},
		&iamentity.User{},
		&iamentity.Role{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newRoleTestOrm(db)
	userRepo, err := userrepo.NewUserRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	groupRepo, err := grouprepo.NewGroupRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}
	roleRepo, err := rolerepo.NewRoleRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}
	authorizer := svc.NewIAMAuthorizer(nil)
	roleService := NewRoleService(roleRepo, userRepo, groupRepo, nil, authorizer, nil, gen.NewUUIDGenerator(), logging.NewNoopLogger())

	ctx := context.Background()
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     "1",
		Permissions:   []string{"*:*:*"},
		ActiveScopeID: 1,
		IsSystem:      true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "test-tenant",
		HomeTenantID:   "test-tenant",
		HomeScopeID:    1,
		ManagedScopeID: 1,
		OwnerID:        svc.TenantOwnerID("test-tenant"),
		Username:       "group-user",
		Email:          "group-user@example.com",
		Password:       "hashed-password",
		Status:         svc.UserStatusActive,
	}
	if err := userRepo.Create(ctx, user, spec.All()); err != nil {
		t.Fatalf("create user: %v", err)
	}

	group := &iamentity.Group{
		TenantID:       "test-tenant",
		ManagedScopeID: 1,
		OwnerID:        svc.TenantOwnerID("test-tenant"),
		Name:           "ops",
		Description:    "ops group",
	}
	if err := groupRepo.Create(ctx, group, spec.All()); err != nil {
		t.Fatalf("create group: %v", err)
	}

	role := &iamentity.Role{
		TenantID:         "test-tenant",
		NamespaceScopeID: 1,
		OwnerID:          svc.TenantOwnerID("test-tenant"),
		Code:             "ops-admin",
		Name:             "ops-admin",
		Description:      "ops admin role",
		Permissions:      iamentity.PermissionArray([]string{"perm:api:via_group"}),
		Status:           svc.RoleStatusActive,
	}
	if err := roleRepo.Create(ctx, role, spec.All()); err != nil {
		t.Fatalf("create role: %v", err)
	}

	if err := userRepo.AssignToGroup(ctx, user.GetID(), group.GetID(), spec.All()); err != nil {
		t.Fatalf("assign user to group: %v", err)
	}
	if err := roleRepo.AssignToGroup(ctx, role.GetID(), group.GetID(), spec.All()); err != nil {
		t.Fatalf("assign role to group: %v", err)
	}

	resp, err := roleService.CheckPermission(ctx, &svc.PermissionCheckRequest{
		UserID:     user.GetID(),
		Permission: "perm:api:via_group",
	})
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !resp.HasPermission {
		t.Fatalf("expected permission inherited from group default role to be allowed")
	}
	if resp.Source != "effective" {
		t.Fatalf("Source = %q, want effective", resp.Source)
	}
	if !slices.Contains(resp.Roles, role.Name) {
		t.Fatalf("Roles = %v, want %q", resp.Roles, role.Name)
	}
}
