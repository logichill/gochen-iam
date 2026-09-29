package user_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gochen/observe/logging"
	"gochen/testkit"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamservice "gochen-iam/service"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	usersvc "gochen-iam/service/user"
	"gochen-iam/tenant"

	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// userServiceTestEnv 用户服务测试环境
type userServiceTestEnv struct {
	db            *gorm.DB
	userService   *usersvc.UserService
	groupService  *groupsvc.GroupService
	userRepo      *userrepo.UserRepo
	groupRepo     *grouprepo.GroupRepo
	roleRepo      *rolerepo.RoleRepo
	tenantRepo    *tenantrepo.TenantRepo
	scopeRepo     *scoperepo.ScopeRepo
	rootScopeID   int64
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
	tenantID      string
}

// setupUserServiceTest 设置测试环境
func setupUserServiceTest(t *testing.T) *userServiceTestEnv {
	// 创建临时目录
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "user_test.db")

	// 配置环境变量
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)
	t.Setenv("IAM_TENANT_MODE", "tenant") // 测试使用 tenant 模式

	// 打开数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ormAdapter := newTestOrm(db)
	if err := iamentity.SetupJoinTables(db); err != nil {
		t.Fatalf("setup join tables: %v", err)
	}

	// 自动迁移表结构
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

	// 创建仓储
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

	// 创建背景上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:   1,
		Permissions: []string{"*:*:*"},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	scopeAuthorizer := iamservice.NewScopeAuthorizer(scopeRepo, tenantRepo)

	tenant := &iamentity.Tenant{
		Key:    "test-tenant",
		Name:   "Test Tenant",
		Status: svc.TenantStatusActive,
	}
	if err := tenantRepo.Create(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	rootScope, err := scopeAuthorizer.EnsureTenantRootScope(ctx, tenant)
	if err != nil {
		t.Fatalf("ensure tenant root scope: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, rootScope.ID, string(rootScope.Type))
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(rootScope.ID))
	if err != nil {
		t.Fatalf("bind tenant root scope: %v", err)
	}
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected principal in background context")
	}
	principal.ActiveScopeID = rootScope.ID
	ctx, err = auth.WithPrincipal(ctx, principal)
	if err != nil {
		t.Fatalf("rebind principal with active scope: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, tenant.Key)
	if err != nil {
		t.Fatalf("rebind tenant context: %v", err)
	}
	ctx = scoped.WithConstraint(ctx, scoped.ConstraintProviderFunc(func(entityType string) (scoped.WriteConstraint, bool) {
		return scoped.WriteConstraint{
			Resources: []scoped.ResourceConstraint{{
				Kind:           entityType,
				TenantID:       tenant.Key,
				ManagedScopeID: rootScope.ID,
				Revision:       "0",
			}},
		}, true
	}))

	authzRegistry, err := iamservice.NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := iamservice.NewIAMAuthorizer(scopeAuthorizer, authzRegistry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	// 创建服务
	userService := usersvc.NewUserService(userRepo, groupRepo, roleRepo, scopeAuthorizer, authorizer, logging.NewNoopLogger())
	groupService := groupsvc.NewGroupService(groupRepo, userRepo, roleRepo, scopeAuthorizer, authorizer, logging.NewNoopLogger())

	return &userServiceTestEnv{
		db:            db,
		userService:   userService,
		groupService:  groupService,
		userRepo:      userRepo,
		groupRepo:     groupRepo,
		roleRepo:      roleRepo,
		tenantRepo:    tenantRepo,
		scopeRepo:     scopeRepo,
		rootScopeID:   rootScope.ID,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
		tenantID:      "test-tenant",
	}
}

// teardown 清理测试环境
func (env *userServiceTestEnv) teardown(t *testing.T) {
	env.cancelFunc()

	sqlDB, err := env.db.DB()
	if err == nil {
		sqlDB.Close()
	}
}

// createTestRole 创建测试角色
func (env *userServiceTestEnv) createTestRole(t *testing.T, name string, permissions []string) *iamentity.Role {
	role := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          svc.TenantOwnerID(env.tenantID),
		NamespaceScopeID: env.rootScopeID,
		Name:             name,
		Description:      "测试角色",
		Permissions:      iamentity.PermissionArray(permissions),
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create test role: %v", err)
	}
	return role
}

// createTestGroup 创建测试组织
func (env *userServiceTestEnv) createTestGroup(t *testing.T, name string, parentID *int64) *iamentity.Group {
	req := &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        name,
		Description: "测试组织",
		ParentID:    parentID,
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create test group: %v", err)
	}
	return group
}

// TestUserServiceRegister 测试用户注册
func TestUserServiceRegister(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	tests := []struct {
		name        string
		req         *svc.RegisterRequest
		expectError bool
		errorCode   errors.ErrorCode
	}{
		{
			name: "正常注册",
			req: &svc.RegisterRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "password123",
			},
			expectError: false,
		},
		{
			name: "用户名已存在",
			req: &svc.RegisterRequest{
				Username: "testuser",
				Email:    "test2@example.com",
				Password: "password123",
			},
			expectError: true,
			errorCode:   errors.Validation,
		},
		{
			name: "邮箱已存在",
			req: &svc.RegisterRequest{
				Username: "testuser2",
				Email:    "test@example.com",
				Password: "password123",
			},
			expectError: true,
			errorCode:   errors.Validation,
		},
		{
			name: "用户名太短",
			req: &svc.RegisterRequest{
				Username: "ab",
				Email:    "test3@example.com",
				Password: "password123",
			},
			expectError: true,
			errorCode:   errors.Validation,
		},
		{
			name: "密码太短",
			req: &svc.RegisterRequest{
				Username: "testuser3",
				Email:    "test4@example.com",
				Password: "12345",
			},
			expectError: true,
			errorCode:   errors.Validation,
		},
		{
			name: "6位密码允许注册",
			req: &svc.RegisterRequest{
				Username: "testuser4",
				Email:    "test5@example.com",
				Password: "123456",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := env.userService.Register(env.backgroundCtx, env.tenantID, tt.req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if appErr, ok := err.(*errors.AppError); ok {
					if appErr.Code() != tt.errorCode {
						t.Errorf("expected error code %s, got %s", tt.errorCode, appErr.Code())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if user == nil {
					t.Error("expected user, got nil")
					return
				}
				if user.Username != tt.req.Username {
					t.Errorf("expected username %s, got %s", tt.req.Username, user.Username)
				}
				if user.Email != tt.req.Email {
					t.Errorf("expected email %s, got %s", tt.req.Email, user.Email)
				}
				if user.Status != svc.UserStatusActive {
					t.Errorf("expected status %s, got %s", svc.UserStatusActive, user.Status)
				}
			}
		})
	}
}

func TestUserServiceAuthenticate_ListsPlatformScopeWhenUserHasPlatformBinding(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	platformScope, err := iamservice.NewScopeAuthorizer(env.scopeRepo, env.tenantRepo).EnsurePlatformScope(env.backgroundCtx)
	if err != nil {
		t.Fatalf("ensure platform scope: %v", err)
	}
	if platformScope.Type != iamentity.ScopeTypePlatform {
		t.Fatalf("expected platform scope, got %s", platformScope.Type)
	}

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "platform_root",
		Email:    "platform@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register platform user: %v", err)
	}

	role := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          svc.TenantOwnerID(env.tenantID),
		NamespaceScopeID: platformScope.ID,
		Name:             svc.SystemAdminRoleName,
		Description:      "平台管理员",
		Permissions:      iamentity.PermissionArray{"*:*:*"},
		IsSystem:         true,
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create platform admin role: %v", err)
	}
	assignCtx := iamauth.BindActiveScopeContext(env.backgroundCtx, platformScope.ID, string(platformScope.Type))
	if err := env.roleRepo.AssignToUser(assignCtx, role.ID, user.ID); err != nil {
		t.Fatalf("assign platform admin role: %v", err)
	}

	authResult, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
		Username: "platform_root",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("authenticate platform user: %v", err)
	}
	found := false
	for _, scope := range authResult.AvailableScopes {
		if scope.ScopeID == platformScope.ID && scope.ScopeKind == iamentity.ScopeTypePlatform {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected authenticate result to include platform scope, got %+v", authResult.AvailableScopes)
	}

	session, err := env.userService.ActivateScope(env.backgroundCtx, user.GetID(), platformScope.ID)
	if err != nil {
		t.Fatalf("activate platform scope: %v", err)
	}
	if session.ActiveScopeID != platformScope.ID {
		t.Fatalf("expected active scope %d, got %d", platformScope.ID, session.ActiveScopeID)
	}
	if len(session.Permissions) == 0 {
		t.Fatalf("expected platform scope permissions, got empty session: %+v", session)
	}
}

func TestTenantRepo_Create_AllowsMultipleTenants(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	first := &iamentity.Tenant{
		Key:    "tenant-a",
		Name:   "Tenant A",
		Status: svc.TenantStatusActive,
	}
	if err := env.tenantRepo.Create(context.Background(), first); err != nil {
		t.Fatalf("create first tenant: %v", err)
	}

	second := &iamentity.Tenant{
		Key:    "tenant-b",
		Name:   "Tenant B",
		Status: svc.TenantStatusActive,
	}
	if err := env.tenantRepo.Create(context.Background(), second); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}
}

// TestUserServiceLogin 测试用户登录
func TestUserServiceLogin(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 先注册一个用户
	registerReq := &svc.RegisterRequest{
		Username: "loginuser",
		Email:    "login@example.com",
		Password: "password123",
	}
	_, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	tests := []struct {
		name        string
		req         *svc.AuthenticateRequest
		expectError bool
	}{
		{
			name: "正常登录",
			req: &svc.AuthenticateRequest{
				Username: "loginuser",
				Password: "password123",
			},
			expectError: false,
		},
		{
			name: "用户名不存在",
			req: &svc.AuthenticateRequest{
				Username: "nonexistent",
				Password: "password123",
			},
			expectError: true,
		},
		{
			name: "密码错误",
			req: &svc.AuthenticateRequest{
				Username: "loginuser",
				Password: "wrongpassword",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, tt.req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if resp == nil {
					t.Error("expected login response, got nil")
					return
				}
				if resp.Username != tt.req.Username {
					t.Errorf("expected username %s, got %s", tt.req.Username, resp.Username)
				}
			}
		})
	}
}

func TestUserServiceAuthPathsRejectDisabledUserAsForbidden(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	tests := []struct {
		name    string
		disable func(ctx context.Context, userID int64) error
	}{
		{
			name:    "inactive",
			disable: env.userService.DeactivateUser,
		},
		{
			name:    "locked",
			disable: env.userService.LockUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registerReq := &svc.RegisterRequest{
				Username: "disabled_auth_" + tt.name,
				Email:    "disabled_auth_" + tt.name + "@example.com",
				Password: "password123",
			}
			user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
			if err != nil {
				t.Fatalf("register user: %v", err)
			}

			if err := tt.disable(env.backgroundCtx, user.GetID()); err != nil {
				t.Fatalf("disable user (%s): %v", tt.name, err)
			}

			_, err = env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
				Username: registerReq.Username,
				Password: registerReq.Password,
			})
			if err == nil {
				t.Fatalf("expected authenticate error for %s user", tt.name)
			}
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("expected forbidden error for authenticate/%s, got %v", tt.name, err)
			}

			_, err = env.userService.AuthSnapshot(env.backgroundCtx, user.GetID(), env.rootScopeID)
			if err == nil {
				t.Fatalf("expected snapshot error for %s user", tt.name)
			}
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("expected forbidden error for snapshot/%s, got %v", tt.name, err)
			}
		})
	}
}

func TestUserServiceAuthSnapshotFiltersInactiveAndDeletedRoles(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	registerReq := &svc.RegisterRequest{
		Username: "snapshot_user",
		Email:    "snapshot@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	activeRole := env.createTestRole(t, "role_active", []string{"perm:api:active"})
	inactiveRole := env.createTestRole(t, "role_inactive", []string{"perm:api:inactive"})
	deletedRole := env.createTestRole(t, "role_deleted", []string{"perm:api:deleted"})

	if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), activeRole.GetID()); err != nil {
		t.Fatalf("assign active role: %v", err)
	}
	if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), inactiveRole.GetID()); err != nil {
		t.Fatalf("assign inactive role: %v", err)
	}
	if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), deletedRole.GetID()); err != nil {
		t.Fatalf("assign deleted role: %v", err)
	}

	inactiveRole.Status = svc.RoleStatusInactive
	inactiveRole.SetUpdatedAt(time.Now())
	inactiveRoleCtx := scoped.WithConstraint(env.backgroundCtx, scoped.SingleEntityConstraint("iam.role", scoped.WriteConstraint{
		Resources: []scoped.ResourceConstraint{{
			Kind:           "iam.role",
			ResourceID:     strconv.FormatInt(inactiveRole.GetID(), 10),
			TenantID:       env.tenantID,
			ManagedScopeID: inactiveRole.NamespaceScopeID,
			Revision:       "0",
		}},
	}))
	if err := env.roleRepo.Update(inactiveRoleCtx, inactiveRole); err != nil {
		t.Fatalf("deactivate role: %v", err)
	}
	deletedRoleCtx := scoped.WithConstraint(env.backgroundCtx, scoped.SingleEntityConstraint("iam.role", scoped.WriteConstraint{
		Resources: []scoped.ResourceConstraint{{
			Kind:           "iam.role",
			ResourceID:     strconv.FormatInt(deletedRole.GetID(), 10),
			TenantID:       env.tenantID,
			ManagedScopeID: deletedRole.NamespaceScopeID,
			Revision:       "0",
		}},
	}))

	if err := env.roleRepo.Delete(deletedRoleCtx, deletedRole.GetID()); err != nil {
		t.Fatalf("soft delete role: %v", err)
	}

	authResp, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
		Username: registerReq.Username,
		Password: registerReq.Password,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	activeResp, err := env.userService.ActivateScope(env.backgroundCtx, user.GetID(), env.rootScopeID)
	if err != nil {
		t.Fatalf("activate scope: %v", err)
	}
	snapshotResp, err := env.userService.AuthSnapshot(env.backgroundCtx, user.GetID(), env.rootScopeID)
	if err != nil {
		t.Fatalf("get auth snapshot: %v", err)
	}

	assertContains := func(list []string, want string, label string) {
		t.Helper()
		for _, item := range list {
			if item == want {
				return
			}
		}
		t.Fatalf("expected %s contains %q, got %v", label, want, list)
	}
	assertNotContains := func(list []string, unwanted string, label string) {
		t.Helper()
		for _, item := range list {
			if item == unwanted {
				t.Fatalf("expected %s not contains %q, got %v", label, unwanted, list)
			}
		}
	}

	scopeOption := func(scopeID int64) *svc.AuthScopeOption {
		for i := range authResp.AvailableScopes {
			if authResp.AvailableScopes[i].ScopeID == scopeID {
				return &authResp.AvailableScopes[i]
			}
		}
		return nil
	}(env.rootScopeID)
	if scopeOption == nil {
		t.Fatalf("expected available scope %d in authenticate response", env.rootScopeID)
	}

	assertContains(scopeOption.RoleNames, "role_active", "auth roles")
	assertNotContains(scopeOption.RoleNames, "role_inactive", "auth roles")
	assertNotContains(scopeOption.RoleNames, "role_deleted", "auth roles")
	assertContains(scopeOption.Permissions, "perm:api:active", "auth permissions")
	assertNotContains(scopeOption.Permissions, "perm:api:inactive", "auth permissions")
	assertNotContains(scopeOption.Permissions, "perm:api:deleted", "auth permissions")

	assertContains(activeResp.RoleNames, "role_active", "active roles")
	assertNotContains(activeResp.RoleNames, "role_inactive", "active roles")
	assertNotContains(activeResp.RoleNames, "role_deleted", "active roles")
	assertContains(activeResp.Permissions, "perm:api:active", "active permissions")
	assertNotContains(activeResp.Permissions, "perm:api:inactive", "active permissions")
	assertNotContains(activeResp.Permissions, "perm:api:deleted", "active permissions")

	assertContains(snapshotResp.RoleNames, "role_active", "snapshot roles")
	assertNotContains(snapshotResp.RoleNames, "role_inactive", "snapshot roles")
	assertNotContains(snapshotResp.RoleNames, "role_deleted", "snapshot roles")
	assertContains(snapshotResp.Permissions, "perm:api:active", "snapshot permissions")
	assertNotContains(snapshotResp.Permissions, "perm:api:inactive", "snapshot permissions")
	assertNotContains(snapshotResp.Permissions, "perm:api:deleted", "snapshot permissions")

	perms, err := env.userService.UserPermissions(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user permissions: %v", err)
	}
	assertContains(perms, "perm:api:active", "user permissions")
	assertNotContains(perms, "perm:api:inactive", "user permissions")
	assertNotContains(perms, "perm:api:deleted", "user permissions")

	allowed, err := env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:api:active")
	if err != nil {
		t.Fatalf("check permission perm:active: %v", err)
	}
	if !allowed {
		t.Fatalf("expected perm:active allowed")
	}
	allowed, err = env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:api:inactive")
	if err != nil {
		t.Fatalf("check permission perm:inactive: %v", err)
	}
	if allowed {
		t.Fatalf("expected perm:inactive denied")
	}
	allowed, err = env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:api:deleted")
	if err != nil {
		t.Fatalf("check permission perm:deleted: %v", err)
	}
	if allowed {
		t.Fatalf("expected perm:deleted denied")
	}
}

func TestUserServiceGetUserPermissionsRequiresActiveUser(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	role := env.createTestRole(t, "perm_role", []string{"perm:api:active"})

	tests := []struct {
		name    string
		disable func(ctx context.Context, userID int64) error
	}{
		{
			name:    "inactive",
			disable: env.userService.DeactivateUser,
		},
		{
			name:    "locked",
			disable: env.userService.LockUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registerReq := &svc.RegisterRequest{
				Username: "permuser_" + tt.name,
				Email:    "permuser_" + tt.name + "@example.com",
				Password: "password123",
			}
			user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
			if err != nil {
				t.Fatalf("register user: %v", err)
			}

			if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID()); err != nil {
				t.Fatalf("assign role: %v", err)
			}

			if err := tt.disable(env.backgroundCtx, user.GetID()); err != nil {
				t.Fatalf("disable user (%s): %v", tt.name, err)
			}

			perms, err := env.userService.UserPermissions(env.backgroundCtx, user.GetID())
			if err == nil {
				t.Fatalf("expected error for %s user, got perms %v", tt.name, perms)
			}
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("expected forbidden error for %s user, got %v", tt.name, err)
			}

			allowed, err := env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:api:active")
			if err == nil {
				t.Fatalf("expected error for %s user, got allowed=%v", tt.name, allowed)
			}
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("expected forbidden error for %s user, got %v", tt.name, err)
			}
			if allowed {
				t.Fatalf("expected allowed=false for %s user", tt.name)
			}
		})
	}
}

func TestUserServiceSingleTenantUsesOneRootScopeForRBAC(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "single_rbac_user",
		Email:    "single-rbac@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	directRole := env.createTestRole(t, "single_direct", []string{"single:api:direct"})
	groupRole := env.createTestRole(t, "single_group", []string{"single:api:group"})
	if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), directRole.GetID()); err != nil {
		t.Fatalf("assign direct role: %v", err)
	}
	bindings, err := env.userRepo.ListRoleBindings(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("list direct role bindings: %v", err)
	}
	if len(bindings) != 1 || bindings[0].GrantScopeID != env.rootScopeID {
		t.Fatalf("expected direct role binding at tenant root %d, got %#v", env.rootScopeID, bindings)
	}
	group := env.createTestGroup(t, "single_group", nil)
	if err := env.groupService.AddGroupRole(env.backgroundCtx, group.GetID(), groupRole.GetID()); err != nil {
		t.Fatalf("assign group role: %v", err)
	}
	if err := env.userService.AssignToGroup(env.backgroundCtx, user.GetID(), group.GetID()); err != nil {
		t.Fatalf("assign user to group: %v", err)
	}
	bindings, err = env.userRepo.ListRoleBindings(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("list role bindings after group assignment: %v", err)
	}
	for _, binding := range bindings {
		if binding.GrantScopeID != env.rootScopeID {
			t.Fatalf("expected all direct bindings at tenant root %d, got %#v", env.rootScopeID, bindings)
		}
	}

	authResult, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
		Username: "single_rbac_user",
		Password: "password123",
	})
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			t.Fatalf("authenticate: %v details=%v", err, appErr.Details())
		}
		t.Fatalf("authenticate: %v", err)
	}
	if len(authResult.AvailableScopes) != 1 {
		t.Fatalf("expected exactly one available scope, got %#v", authResult.AvailableScopes)
	}
	option := authResult.AvailableScopes[0]
	if option.ScopeID != env.rootScopeID || option.ScopeKind != iamentity.ScopeTypeTenant {
		t.Fatalf("expected tenant root scope %d, got %#v", env.rootScopeID, option)
	}
	assertStringContains(t, option.RoleNames, directRole.Name)
	assertStringContains(t, option.RoleNames, groupRole.Name)
	assertStringContains(t, option.Permissions, "single:api:direct")
	assertStringContains(t, option.Permissions, "single:api:group")

	session, err := env.userService.ActivateScope(env.backgroundCtx, user.GetID(), env.rootScopeID)
	if err != nil {
		t.Fatalf("activate root scope: %v", err)
	}
	if session.BindingVersion != authResult.BindingVersion {
		t.Fatalf("binding version changed without authorization changes: %q != %q", session.BindingVersion, authResult.BindingVersion)
	}
}

func TestUserServiceAuthSnapshotQueryCountIsBounded(t *testing.T) {
	for _, mode := range []string{"tenant", "single"} {
		t.Run(mode, func(t *testing.T) {
			var baseline int
			for _, bindingCount := range []int{1, 10, 100} {
				t.Run(strconv.Itoa(bindingCount), func(t *testing.T) {
					env := setupUserServiceTest(t)
					defer env.teardown(t)
					env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.Mode(mode), SingleTenantID: env.tenantID})

					user := &iamentity.User{
						TenantID:       env.tenantID,
						HomeTenantID:   env.tenantID,
						HomeScopeID:    env.rootScopeID,
						ManagedScopeID: env.rootScopeID,
						OwnerID:        svc.TenantOwnerID(env.tenantID),
						Username:       "bounded_query_user",
						Email:          "bounded-query@example.com",
						Password:       "password-hash",
						Status:         svc.UserStatusActive,
					}
					if err := env.userRepo.Create(env.backgroundCtx, user); err != nil {
						t.Fatalf("create user: %v", err)
					}
					for i := 0; i < bindingCount; i++ {
						directRole := env.createTestRole(t, "bounded_direct_"+strconv.Itoa(i), []string{"bounded:api:direct:" + strconv.Itoa(i)})
						if err := env.db.Create(&iamentity.UserRoleBinding{
							UserID:       user.GetID(),
							RoleID:       directRole.GetID(),
							GrantScopeID: env.rootScopeID,
							Status:       "active",
						}).Error; err != nil {
							t.Fatalf("create direct role binding %d: %v", i, err)
						}

						groupRole := env.createTestRole(t, "bounded_group_"+strconv.Itoa(i), []string{"bounded:api:group:" + strconv.Itoa(i)})
						group := &iamentity.Group{
							TenantID:       env.tenantID,
							ManagedScopeID: env.rootScopeID,
							OwnerID:        svc.TenantOwnerID(env.tenantID),
							Name:           "bounded_group_" + strconv.Itoa(i),
							ParentKey:      0,
							Level:          1,
						}
						if err := env.db.Create(group).Error; err != nil {
							t.Fatalf("create group %d: %v", i, err)
						}
						if err := env.db.Exec("INSERT INTO group_roles (group_id, role_id) VALUES (?, ?)", group.GetID(), groupRole.GetID()).Error; err != nil {
							t.Fatalf("create group role %d: %v", i, err)
						}
						if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.GetID(), group.GetID()).Error; err != nil {
							t.Fatalf("create user group %d: %v", i, err)
						}
					}

					queryCount := 0
					if err := env.db.Callback().Query().Before("gorm:query").Register("test:auth_snapshot_query_count", func(*gorm.DB) {
						queryCount++
					}); err != nil {
						t.Fatalf("register query counter: %v", err)
					}
					snapshot, err := env.userService.AuthSnapshot(env.backgroundCtx, user.GetID(), env.rootScopeID)
					if err != nil {
						t.Fatalf("auth snapshot: %v", err)
					}
					if len(snapshot.RoleNames) != 2*bindingCount {
						t.Fatalf("role count = %d, want %d", len(snapshot.RoleNames), 2*bindingCount)
					}
					if baseline == 0 {
						baseline = queryCount
					}
					if queryCount != baseline {
						t.Fatalf("query count = %d for %d direct and group bindings, want constant %d", queryCount, bindingCount, baseline)
					}
				})
			}
		})
	}
}

func TestUserServiceSingleTenantProjectsAncestorGrantIntoRootScope(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "single_platform_admin",
		Email:    "single-platform-admin@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	platformScope, err := iamservice.NewScopeAuthorizer(env.scopeRepo, env.tenantRepo).EnsurePlatformScope(env.backgroundCtx)
	if err != nil {
		t.Fatalf("ensure platform scope: %v", err)
	}
	platformRole := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          "platform",
		NamespaceScopeID: platformScope.ID,
		Name:             "single_platform_admin",
		Description:      "single 模式平台祖先域角色",
		Permissions:      iamentity.PermissionArray{"*:*:*"},
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, platformRole); err != nil {
		t.Fatalf("create platform role: %v", err)
	}
	binding := &iamentity.UserRoleBinding{
		UserID:       user.GetID(),
		RoleID:       platformRole.GetID(),
		GrantScopeID: platformScope.ID,
		Status:       "active",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := env.db.Create(binding).Error; err != nil {
		t.Fatalf("seed platform binding: %v", err)
	}

	authResult, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
		Username: "single_platform_admin",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if len(authResult.AvailableScopes) != 1 || authResult.AvailableScopes[0].ScopeID != env.rootScopeID {
		t.Fatalf("expected one tenant root scope, got %#v", authResult.AvailableScopes)
	}
	assertStringContains(t, authResult.AvailableScopes[0].RoleNames, platformRole.Name)
	assertStringContains(t, authResult.AvailableScopes[0].Permissions, "*:*:*")

	details, err := env.userService.UserRoleBindings(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("list projected binding: %v", err)
	}
	if len(details) != 1 || details[0].BindingID != binding.ID || details[0].RoleName != platformRole.Name {
		t.Fatalf("expected projected platform binding to remain manageable, got %#v", details)
	}
	if err := env.userService.RemoveRoleBinding(env.backgroundCtx, user.GetID(), binding.ID); err != nil {
		t.Fatalf("remove projected binding: %v", err)
	}
	remaining, err := env.userRepo.ListRoleBindings(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("list remaining bindings: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected projected binding removal, got %#v", remaining)
	}
}

func TestUserServiceSingleTenantRejectsExplicitOrExistingNonCoveringGrant(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "single_invalid_grant",
		Email:    "single-invalid-grant@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}
	role := env.createTestRole(t, "single_invalid_grant_role", []string{"single:api:test"})
	nonRootScopeID := env.rootScopeID + 1000
	if err := env.userService.AssignRoleBinding(env.backgroundCtx, user.GetID(), role.GetID(), &nonRootScopeID); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("expected explicit non-root grant to fail, got %v", err)
	}
	if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID()); err != nil {
		t.Fatalf("assign root role: %v", err)
	}
	if result := env.db.Model(&iamentity.UserRoleBinding{}).
		Where("user_id = ? AND role_id = ?", user.GetID(), role.GetID()).
		Update("grant_scope_id", nonRootScopeID); result.Error != nil {
		t.Fatalf("move binding to non-root scope: %v", result.Error)
	}

	_, err = env.userService.Authenticate(env.backgroundCtx, env.tenantID, &svc.AuthenticateRequest{
		Username: "single_invalid_grant",
		Password: "password123",
	})
	if !errors.Is(err, errors.Conflict) {
		t.Fatalf("expected existing non-covering binding to fail closed, got %v", err)
	}
}

func assertStringContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("expected %q in %v", want, values)
}

// TestUserServiceChangePassword 测试修改密码
func TestUserServiceChangePassword(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "pwduser",
		Email:    "pwd@example.com",
		Password: "oldpassword",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 修改密码
	changeReq := &svc.ChangePasswordRequest{
		OldPassword: "oldpassword",
		NewPassword: "newpassword123",
	}
	err = env.userService.ChangePassword(env.backgroundCtx, user.GetID(), changeReq)
	if err != nil {
		t.Fatalf("change password: %v", err)
	}

	// 验证旧密码无法登录
	loginReq := &svc.AuthenticateRequest{
		Username: "pwduser",
		Password: "oldpassword",
	}
	_, err = env.userService.Authenticate(env.backgroundCtx, env.tenantID, loginReq)
	if err == nil {
		t.Error("expected login to fail with old password")
	}

	// 验证新密码可以登录
	loginReq.Password = "newpassword123"
	resp, err := env.userService.Authenticate(env.backgroundCtx, env.tenantID, loginReq)
	if err != nil {
		t.Errorf("login with new password failed: %v", err)
	}
	if resp == nil {
		t.Error("expected login response, got nil")
	}
}

// TestUserServiceUpdateProfile 测试更新用户资料
func TestUserServiceUpdateProfile(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "profileuser",
		Email:    "profile@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 更新资料
	updateReq := &svc.UpdateUserRequest{
		Email:  "newemail@example.com",
		Avatar: "https://example.com/avatar.jpg",
	}
	updatedUser, err := env.userService.UpdateProfile(env.backgroundCtx, user.GetID(), updateReq)
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}

	if updatedUser.Email != updateReq.Email {
		t.Errorf("expected email %s, got %s", updateReq.Email, updatedUser.Email)
	}
	if updatedUser.Avatar != updateReq.Avatar {
		t.Errorf("expected avatar %s, got %s", updateReq.Avatar, updatedUser.Avatar)
	}
}

// TestUserServiceActivateDeactivate 测试激活和停用用户
func TestUserServiceActivateDeactivate(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "statususer",
		Email:    "status@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 停用用户
	err = env.userService.DeactivateUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("deactivate user: %v", err)
	}

	// 验证状态
	dbUser, err := env.userRepo.Get(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if dbUser.Status != svc.UserStatusInactive {
		t.Errorf("expected status %s, got %s", svc.UserStatusInactive, dbUser.Status)
	}

	// 激活用户
	err = env.userService.ActivateUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("activate user: %v", err)
	}

	// 验证状态
	dbUser, err = env.userRepo.Get(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if dbUser.Status != svc.UserStatusActive {
		t.Errorf("expected status %s, got %s", svc.UserStatusActive, dbUser.Status)
	}
}

func TestUserServiceActivateUserRejectsPlatformOwnedUserFromTenantScopeInSingleTenant(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})

	platformScope, err := iamservice.NewScopeAuthorizer(env.scopeRepo, env.tenantRepo).EnsurePlatformScope(env.backgroundCtx)
	if err != nil {
		t.Fatalf("ensure platform scope: %v", err)
	}
	platformCtx := iamauth.BindActiveScopeContext(env.backgroundCtx, platformScope.ID, string(platformScope.Type))
	platformCtx, err = scoped.WithDataScope(platformCtx, scoped.Filtered(platformScope.ID))
	if err != nil {
		t.Fatalf("bind platform data scope: %v", err)
	}
	platformPrincipal, ok := auth.PrincipalFromContext(platformCtx)
	if !ok {
		t.Fatal("expected platform principal")
	}
	platformPrincipal.ActiveScopeID = platformScope.ID
	platformCtx, err = auth.WithPrincipal(platformCtx, platformPrincipal)
	if err != nil {
		t.Fatalf("bind platform principal: %v", err)
	}

	placeholder := &iamentity.User{
		TenantID:       env.tenantID,
		HomeTenantID:   env.tenantID,
		HomeScopeID:    platformScope.ID,
		ManagedScopeID: platformScope.ID,
		OwnerID:        "platform",
		Username:       "bootstrap-admin",
		Email:          "bootstrap-admin@example.com",
		Password:       "!ACTIVATION_REQUIRED!",
		Status:         svc.UserStatusInactive,
	}
	if err := env.userRepo.Create(platformCtx, placeholder); err != nil {
		t.Fatalf("create platform-owned placeholder: %v", err)
	}

	tenantPrincipal := auth.Principal{
		SubjectID:     42,
		Permissions:   []string{"user:api:*"},
		ActiveScopeID: env.rootScopeID,
	}
	tenantCtx, err := auth.WithPrincipal(env.backgroundCtx, tenantPrincipal)
	if err != nil {
		t.Fatalf("bind tenant principal: %v", err)
	}
	if err := env.userService.ActivateUser(tenantCtx, placeholder.GetID()); err == nil {
		t.Fatal("expected platform-owned placeholder activation to be rejected")
	} else if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected forbidden activation, got %v", err)
	}

	stored, err := env.userRepo.Get(platformCtx, placeholder.GetID())
	if err != nil {
		t.Fatalf("reload platform-owned placeholder: %v", err)
	}
	if stored.Status != svc.UserStatusInactive {
		t.Fatalf("platform-owned user status = %q, want inactive", stored.Status)
	}
}

// TestUserServiceLockUnlock 测试锁定和解锁用户
func TestUserServiceLockUnlock(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "lockuser",
		Email:    "lock@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 锁定用户
	err = env.userService.LockUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("lock user: %v", err)
	}

	// 验证状态
	dbUser, err := env.userRepo.Get(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if dbUser.Status != svc.UserStatusLocked {
		t.Errorf("expected status %s, got %s", svc.UserStatusLocked, dbUser.Status)
	}

	// 解锁用户
	err = env.userService.UnlockUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("unlock user: %v", err)
	}

	// 验证状态
	dbUser, err = env.userRepo.Get(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if dbUser.Status != svc.UserStatusActive {
		t.Errorf("expected status %s, got %s", svc.UserStatusActive, dbUser.Status)
	}
}

// TestUserServiceAssignRole 测试分配角色
func TestUserServiceAssignRole(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "roleuser",
		Email:    "role@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建角色
	role := env.createTestRole(t, "test_role", []string{"test:api:read", "test:api:write"})

	// 分配角色
	err = env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID())
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}

	// 验证角色
	roles, err := env.userService.UserRoles(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user roles: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("expected 1 role, got %d", len(roles))
	}
	if len(roles) > 0 && roles[0].Name != "test_role" {
		t.Errorf("expected role name test_role, got %s", roles[0].Name)
	}
}

func TestUserRepoAssignRoleWithConstraint_AllowsSameTenantDifferentManagedScopes(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "scopedroleuser",
		Email:    "scopedrole@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	rootScope, err := env.scopeRepo.Get(env.backgroundCtx, env.rootScopeID)
	if err != nil {
		t.Fatalf("get root scope: %v", err)
	}
	childScope := &iamentity.Scope{
		Key:      "tenant:test-tenant:child",
		Name:     "Child Scope",
		Type:     "department",
		ParentID: &rootScope.ID,
		Path:     iamentity.ScopePathFor(rootScope.Path, "child"),
		Depth:    rootScope.Depth + 1,
		Status:   iamentity.ScopeStatusActive,
	}
	scopeGuard, err := svc.NewPlatformCreateConstraint(env.backgroundCtx, svc.ScopeResourceKind)
	if err != nil {
		t.Fatalf("NewPlatformCreateConstraint: %v", err)
	}
	if err := env.scopeRepo.CreateWithConstraint(env.backgroundCtx, childScope, scopeGuard); err != nil {
		t.Fatalf("create child scope: %v", err)
	}

	role := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          svc.TenantOwnerID(env.tenantID),
		NamespaceScopeID: childScope.ID,
		Name:             "child_scope_role",
		Description:      "child scope role",
		Permissions:      iamentity.PermissionArray([]string{"test:api:read"}),
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create child scope role: %v", err)
	}

	guard := iamaccess.NewWriteConstraint(scoped.WriteConstraint{
		Resources: []scoped.ResourceConstraint{

			{
				Kind:           svc.UserResourceKind,
				ResourceID:     guardID(user.GetID()),
				ManagedScopeID: user.ManagedScopeID,
				TenantID:       env.tenantID,
			},
			{
				Kind:           svc.RoleResourceKind,
				ResourceID:     guardID(role.GetID()),
				ManagedScopeID: role.NamespaceScopeID,
				TenantID:       env.tenantID,
			},
		},
	})

	if err := env.userRepo.AssignRoleWithConstraint(env.backgroundCtx, user.GetID(), role.GetID(), guard); err != nil {
		t.Fatalf("AssignRoleWithConstraint: %v", err)
	}

	bindings, err := env.userRepo.ListRoleBindings(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 role binding, got %d", len(bindings))
	}
	if bindings[0].RoleID != role.GetID() {
		t.Fatalf("expected role %d, got %d", role.GetID(), bindings[0].RoleID)
	}

	guard.Resources[1].TenantID = "other-tenant"
	if err := env.userRepo.AssignRoleWithConstraint(env.backgroundCtx, user.GetID(), role.GetID(), guard); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected cross-tenant guard to be forbidden, got %v", err)
	}
}

func guardID(id int64) string {
	return strconv.FormatInt(id, 10)
}

// TestUserServiceAssignToGroup 测试加入组织
func TestUserServiceAssignToGroup(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "groupuser",
		Email:    "group@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建组织
	group := env.createTestGroup(t, "测试组织", nil)

	// 加入组织
	err = env.userService.AssignToGroup(env.backgroundCtx, user.GetID(), group.GetID())
	if err != nil {
		t.Fatalf("assign to group: %v", err)
	}

	// 验证组织
	groups, err := env.userService.UserGroups(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user groups: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
	if len(groups) > 0 && groups[0].Name != "测试组织" {
		t.Errorf("expected group name 测试组织, got %s", groups[0].Name)
	}
}

// TestUserServiceRemoveRole 测试移除角色
func TestUserServiceRemoveRole(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "removeroleuser",
		Email:    "removerole@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建并分配角色
	role := env.createTestRole(t, "remove_role", []string{"test:api:read"})
	err = env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID())
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}

	// 移除角色
	err = env.userService.RemoveRole(env.backgroundCtx, user.GetID(), role.GetID())
	if err != nil {
		t.Fatalf("remove role: %v", err)
	}

	// 验证角色已移除
	roles, err := env.userService.UserRoles(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user roles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

// TestUserServiceRemoveFromGroup 测试离开组织
func TestUserServiceRemoveFromGroup(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	// 注册用户
	registerReq := &svc.RegisterRequest{

		Username: "removegroupuser",
		Email:    "removegroup@example.com",
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建组织并加入
	group := env.createTestGroup(t, "移除测试组织", nil)
	err = env.userService.AssignToGroup(env.backgroundCtx, user.GetID(), group.GetID())
	if err != nil {
		t.Fatalf("assign to group: %v", err)
	}

	// 离开组织
	err = env.userService.RemoveFromGroup(env.backgroundCtx, user.GetID(), group.GetID())
	if err != nil {
		t.Fatalf("remove from group: %v", err)
	}

	// 验证已离开
	groups, err := env.userService.UserGroups(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

func TestUserServiceAssignRoleMasksCrossTenantRoleAsNotFound(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "crossroleuser",
		Email:    "crossrole@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	otherCtx, err := svc.BindTenantContext(env.backgroundCtx, "other-tenant")
	if err != nil {
		t.Fatalf("BindTenantContext(other): %v", err)
	}
	otherCtx = scoped.WithConstraint(otherCtx, scoped.ConstraintProviderFunc(func(entityType string) (scoped.WriteConstraint, bool) {
		return scoped.WriteConstraint{
			Resources: []scoped.ResourceConstraint{{
				Kind:           entityType,
				TenantID:       "other-tenant",
				ManagedScopeID: 1,
				Revision:       "0",
			}},
		}, true
	}))
	otherRole := &iamentity.Role{
		TenantID:         "other-tenant",
		OwnerID:          svc.TenantOwnerID("other-tenant"),
		NamespaceScopeID: 1,
		Name:             "other-role",
		Description:      "cross tenant role",
		Permissions:      iamentity.PermissionArray([]string{"test:api:read"}),
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(otherCtx, otherRole); err != nil {
		t.Fatalf("create other tenant role: %v", err)
	}

	err = env.userService.AssignRole(env.backgroundCtx, user.GetID(), otherRole.GetID())
	if !errors.Is(err, errors.NotFound) {
		t.Fatalf("expected NotFound for cross-tenant role assignment, got %v", err)
	}
}

func TestUserServiceAssignToGroupMasksCrossTenantGroupAsNotFound(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)

	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, &svc.RegisterRequest{
		Username: "crossgroupuser",
		Email:    "crossgroup@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	otherCtx, err := svc.BindTenantContext(env.backgroundCtx, "other-tenant")
	if err != nil {
		t.Fatalf("BindTenantContext(other): %v", err)
	}
	otherCtx = scoped.WithConstraint(otherCtx, scoped.ConstraintProviderFunc(func(entityType string) (scoped.WriteConstraint, bool) {
		return scoped.WriteConstraint{
			Resources: []scoped.ResourceConstraint{{
				Kind:           entityType,
				TenantID:       "other-tenant",
				ManagedScopeID: 1,
				Revision:       "0",
			}},
		}, true
	}))

	otherTenant := &iamentity.Tenant{
		Key:    "other-tenant",
		Name:   "Other Tenant",
		Status: svc.TenantStatusActive,
	}
	if err := env.tenantRepo.Create(env.backgroundCtx, otherTenant); err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	if _, err := iamservice.NewScopeAuthorizer(env.scopeRepo, env.tenantRepo).EnsureTenantRootScope(env.backgroundCtx, otherTenant); err != nil {
		t.Fatalf("ensure other tenant root scope: %v", err)
	}
	otherGroup, err := env.groupService.CreateGroup(otherCtx, &svc.CreateGroupRequest{
		TenantID:    "other-tenant",
		Name:        "other-group",
		Description: "cross tenant group",
	})
	if err != nil {
		t.Fatalf("create other tenant group: %v", err)
	}

	err = env.userService.AssignToGroup(env.backgroundCtx, user.GetID(), otherGroup.GetID())
	if !errors.Is(err, errors.NotFound) {
		t.Fatalf("expected NotFound for cross-tenant group assignment, got %v", err)
	}
}
