package role

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	usersvc "gochen-iam/service/user"
	auth "gochen/auth/core"
	"gochen/contextx"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type roleBatchTestEnv struct {
	db            *gorm.DB
	roleService   *RoleService
	userService   *usersvc.UserService
	roleRepo      *rolerepo.RoleRepo
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
	tenantID      string
}

func setupRoleBatchTest(t *testing.T) *roleBatchTestEnv {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "role_batch_test.db")

	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)
	t.Setenv("IAM_TENANT_MODE", "tenant")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ormAdapter := newRoleTestOrm(db)
	if err := iamentity.SetupJoinTables(db); err != nil {
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

	groupRepo, err := grouprepo.NewGroupRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}
	userRepo, err := userrepo.NewUserRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	roleRepo, err := rolerepo.NewRoleRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}
	authzRegistry, err := svc.NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := svc.NewIAMAuthorizer(nil, authzRegistry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	roleService := NewRoleService(roleRepo, userRepo, groupRepo, nil, authorizer, nil)
	userService := usersvc.NewUserService(userRepo, groupRepo, roleRepo, nil, authorizer)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     1,
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

	return &roleBatchTestEnv{
		db:            db,
		roleService:   roleService,
		userService:   userService,
		roleRepo:      roleRepo,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
		tenantID:      "test-tenant",
	}
}

func (env *roleBatchTestEnv) teardown(t *testing.T) {
	env.cancelFunc()

	sqlDB, err := env.db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

func (env *roleBatchTestEnv) createTestUser(t *testing.T, username, email string) *iamentity.User {
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: username,
		Email:    email,
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user
}

func (env *roleBatchTestEnv) createTestRole(t *testing.T, name string) *iamentity.Role {
	role := &iamentity.Role{
		TenantID:         env.tenantID,
		NamespaceScopeID: 1,
		OwnerID:          svc.TenantOwnerID(env.tenantID),
		Code:             name,
		Name:             name,
		Description:      "批量角色分配测试",
		Permissions:      iamentity.PermissionArray([]string{"api:test:read"}),
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create test role: %v", err)
	}
	return role
}

func TestRoleServiceBatchAssignRole_RollsBackOnFailure(t *testing.T) {
	env := setupRoleBatchTest(t)
	defer env.teardown(t)

	role := env.createTestRole(t, "batch-role")
	user1 := env.createTestUser(t, "rolebatch1", "rolebatch1@example.com")
	user2 := env.createTestUser(t, "rolebatch2", "rolebatch2@example.com")

	resp, err := env.roleService.BatchAssignRole(env.backgroundCtx, &svc.RoleAssignRequest{
		RoleID:  role.GetID(),
		UserIDs: []int64{user1.GetID(), -1, user2.GetID()},
	})
	if err != nil {
		t.Fatalf("batch assign role with rollback: %v", err)
	}

	if resp.SuccessCount != 0 {
		t.Errorf("expected success count 0 after rollback, got %d", resp.SuccessCount)
	}
	if resp.FailureCount != 1 {
		t.Errorf("expected failure count 1, got %d", resp.FailureCount)
	}
	if len(resp.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(resp.Errors))
	}

	var bindingCount int64
	if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&bindingCount).Error; err != nil {
		t.Fatalf("count user role bindings: %v", err)
	}
	if bindingCount != 0 {
		t.Errorf("expected 0 role bindings after rollback, got %d", bindingCount)
	}
}
