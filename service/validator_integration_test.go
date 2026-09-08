package service

import (
	"context"
	"gochen/testkit"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/crud"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type validatorTestEnv struct {
	db            *gorm.DB
	validator     *BusinessValidator
	userRepo      *userrepo.UserRepo
	groupRepo     *grouprepo.GroupRepo
	roleRepo      *rolerepo.RoleRepo
	tenantRepo    *tenantrepo.TenantRepo
	scopeRepo     *scoperepo.ScopeRepo
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
	tenantID      string
	rootScopeID   int64
}

func setupValidatorTest(t *testing.T) *validatorTestEnv {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "validator_test.db")

	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)
	t.Setenv(tenant.EnvTenantMode, string(tenant.ModeTenant))

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := iamentity.SetupJoinTables(db); err != nil {
		t.Fatalf("setup join tables: %v", err)
	}
	if err := db.AutoMigrate(
		&iamentity.Scope{},
		&iamentity.ScopeVisibility{},
		&iamentity.Tenant{},
		&iamentity.UserRoleBinding{},
		&iamentity.User{},
		&iamentity.Group{},
		&iamentity.Role{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeAuthorizerTestOrm(db)
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
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:   1,
		Permissions: []string{AdminEntryPermission.Code},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	tenantRow := &iamentity.Tenant{
		Entity: crud.Entity[int64]{ID: 1},
		Key:    "test-tenant",
		Name:   "Test Tenant",
		Status: TenantStatusActive,
	}
	if err := tenantRepo.Create(ctx, tenantRow); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	scopeAuthorizer := NewScopeAuthorizer(scopeRepo, tenantRepo)
	rootScope, err := scopeAuthorizer.EnsureTenantRootScope(ctx, tenantRow)
	if err != nil {
		t.Fatalf("ensure tenant root scope: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, rootScope.ID, string(rootScope.Type))
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(rootScope.ID))
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected principal in context")
	}
	principal.ActiveScopeID = rootScope.ID
	ctx, err = auth.WithPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("rebind principal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, tenantRow.Key)
	if err != nil {
		t.Fatalf("rebind tenant context: %v", err)
	}
	ctx = scoped.WithConstraint(ctx, scoped.ConstraintProviderFunc(func(entityType string) (scoped.WriteConstraint, bool) {
		return scoped.WriteConstraint{
			Resources: []scoped.ResourceConstraint{{
				Kind:           entityType,
				TenantID:       tenantRow.Key,
				ManagedScopeID: rootScope.ID,
				Revision:       "0",
			}},
		}, true
	}))

	return &validatorTestEnv{
		db:            db,
		validator:     NewBusinessValidator(userRepo, groupRepo, roleRepo),
		userRepo:      userRepo,
		groupRepo:     groupRepo,
		roleRepo:      roleRepo,
		tenantRepo:    tenantRepo,
		scopeRepo:     scopeRepo,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
		tenantID:      tenantRow.Key,
		rootScopeID:   rootScope.ID,
	}
}

func (env *validatorTestEnv) teardown(t *testing.T) {
	t.Helper()
	env.cancelFunc()
	sqlDB, err := env.db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

func (env *validatorTestEnv) createUser(t *testing.T, username string) *iamentity.User {
	t.Helper()
	user := &iamentity.User{
		TenantID:       env.tenantID,
		HomeTenantID:   env.tenantID,
		HomeScopeID:    env.rootScopeID,
		ManagedScopeID: env.rootScopeID,
		OwnerID:        TenantOwnerID(env.tenantID),
		Username:       username,
		Email:          username + "@example.com",
		Password:       "hashed-password",
		Status:         UserStatusActive,
	}
	if err := env.userRepo.Create(env.backgroundCtx, user); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return user
}

func (env *validatorTestEnv) createGroup(t *testing.T, name string) *iamentity.Group {
	t.Helper()
	group := &iamentity.Group{
		TenantID:       env.tenantID,
		ManagedScopeID: env.rootScopeID,
		OwnerID:        TenantOwnerID(env.tenantID),
		Name:           name,
		Description:    "validator integration group",
	}
	if err := env.groupRepo.Create(env.backgroundCtx, group); err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	return group
}

func (env *validatorTestEnv) createRole(t *testing.T, name string, permissions []string) *iamentity.Role {
	t.Helper()
	role := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          TenantOwnerID(env.tenantID),
		NamespaceScopeID: env.rootScopeID,
		Name:             name,
		Description:      "validator integration role",
		Permissions:      iamentity.PermissionArray(permissions),
		Status:           RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return role
}

func TestValidateUserDeletionRejectsLastAdminInheritedFromGroupDefaultRole(t *testing.T) {
	env := setupValidatorTest(t)
	defer env.teardown(t)

	user := env.createUser(t, "only-admin")
	group := env.createGroup(t, "admin-group")
	role := env.createRole(t, "group-admin", []string{AdminEntryPermission.Code})

	if err := env.userRepo.AssignToGroup(env.backgroundCtx, user.GetID(), group.GetID()); err != nil {
		t.Fatalf("AssignToGroup(user): %v", err)
	}
	if err := env.roleRepo.AssignToGroup(env.backgroundCtx, role.GetID(), group.GetID()); err != nil {
		t.Fatalf("AssignToGroup(role): %v", err)
	}

	err := env.validator.ValidateUserDeletion(env.backgroundCtx, user.GetID())
	if err == nil || !strings.Contains(err.Error(), "不能删除最后一个管理员") {
		t.Fatalf("ValidateUserDeletion error = %v, want last-admin rejection", err)
	}
}

func TestValidateUserDeletionAllowsRemovalWhenAnotherGroupAdminRemains(t *testing.T) {
	env := setupValidatorTest(t)
	defer env.teardown(t)

	deletingUser := env.createUser(t, "admin-a")
	remainingUser := env.createUser(t, "admin-b")
	group := env.createGroup(t, "admin-group")
	role := env.createRole(t, "group-admin", []string{AdminEntryPermission.Code})

	if err := env.userRepo.AssignToGroup(env.backgroundCtx, deletingUser.GetID(), group.GetID()); err != nil {
		t.Fatalf("AssignToGroup(deleting user): %v", err)
	}
	if err := env.userRepo.AssignToGroup(env.backgroundCtx, remainingUser.GetID(), group.GetID()); err != nil {
		t.Fatalf("AssignToGroup(remaining user): %v", err)
	}
	if err := env.roleRepo.AssignToGroup(env.backgroundCtx, role.GetID(), group.GetID()); err != nil {
		t.Fatalf("AssignToGroup(role): %v", err)
	}

	if err := env.validator.ValidateUserDeletion(env.backgroundCtx, deletingUser.GetID()); err != nil {
		t.Fatalf("ValidateUserDeletion: %v", err)
	}
}
