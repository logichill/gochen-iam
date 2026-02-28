package user_test

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
	groupsvc "gochen-iam/service/group"
	usersvc "gochen-iam/service/user"

	"gochen/errorx"
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
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
}

// setupUserServiceTest 设置测试环境
func setupUserServiceTest(t *testing.T) *userServiceTestEnv {
	// 创建临时目录
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "user_test.db")

	// 配置环境变量
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)

	// 打开数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ormAdapter := newTestOrm(db)

	// 自动迁移表结构
	if err := db.AutoMigrate(
		&iamentity.User{},
		&iamentity.Group{},
		&iamentity.Role{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	// 创建仓储
	userRepo, err := userrepo.NewUserRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	groupRepo, err := grouprepo.NewGroupRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}
	roleRepo, err := rolerepo.NewRoleRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	// 创建服务
	userService := usersvc.NewUserService(userRepo, groupRepo, roleRepo)
	groupService := groupsvc.NewGroupService(groupRepo, userRepo, roleRepo)

	// 创建背景上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	return &userServiceTestEnv{
		db:            db,
		userService:   userService,
		groupService:  groupService,
		userRepo:      userRepo,
		groupRepo:     groupRepo,
		roleRepo:      roleRepo,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
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
		Name:        name,
		Description: "测试角色",
		Permissions: iamentity.PermissionArray(permissions),
		Status:      svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create test role: %v", err)
	}
	return role
}

// createTestGroup 创建测试组织
func (env *userServiceTestEnv) createTestGroup(t *testing.T, name string, parentID *int64) *iamentity.Group {
	req := &svc.CreateGroupRequest{
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
		errorCode   errorx.ErrorCode
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
			errorCode:   errorx.Validation,
		},
		{
			name: "邮箱已存在",
			req: &svc.RegisterRequest{
				Username: "testuser2",
				Email:    "test@example.com",
				Password: "password123",
			},
			expectError: true,
			errorCode:   errorx.Validation,
		},
		{
			name: "用户名太短",
			req: &svc.RegisterRequest{
				Username: "ab",
				Email:    "test3@example.com",
				Password: "password123",
			},
			expectError: true,
			errorCode:   errorx.Validation,
		},
		{
			name: "密码太短",
			req: &svc.RegisterRequest{
				Username: "testuser3",
				Email:    "test4@example.com",
				Password: "12345",
			},
			expectError: true,
			errorCode:   errorx.Validation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := env.userService.Register(env.backgroundCtx, tt.req)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if appErr, ok := err.(*errorx.AppError); ok {
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
	_, err := env.userService.Register(env.backgroundCtx, registerReq)
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
			resp, err := env.userService.Authenticate(env.backgroundCtx, tt.req)

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
			user, err := env.userService.Register(env.backgroundCtx, registerReq)
			if err != nil {
				t.Fatalf("register user: %v", err)
			}

			if err := tt.disable(env.backgroundCtx, user.GetID()); err != nil {
				t.Fatalf("disable user (%s): %v", tt.name, err)
			}

			_, err = env.userService.Authenticate(env.backgroundCtx, &svc.AuthenticateRequest{
				Username: registerReq.Username,
				Password: registerReq.Password,
			})
			if err == nil {
				t.Fatalf("expected authenticate error for %s user", tt.name)
			}
			if !errorx.Is(err, errorx.Forbidden) {
				t.Fatalf("expected forbidden error for authenticate/%s, got %v", tt.name, err)
			}

			_, err = env.userService.GetAuthSnapshot(env.backgroundCtx, user.GetID())
			if err == nil {
				t.Fatalf("expected snapshot error for %s user", tt.name)
			}
			if !errorx.Is(err, errorx.Forbidden) {
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	activeRole := env.createTestRole(t, "role_active", []string{"perm:active"})
	inactiveRole := env.createTestRole(t, "role_inactive", []string{"perm:inactive"})
	deletedRole := env.createTestRole(t, "role_deleted", []string{"perm:deleted"})

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
	if err := env.roleRepo.Update(env.backgroundCtx, inactiveRole); err != nil {
		t.Fatalf("deactivate role: %v", err)
	}
	if err := env.roleRepo.Delete(env.backgroundCtx, deletedRole.GetID()); err != nil {
		t.Fatalf("soft delete role: %v", err)
	}

	authResp, err := env.userService.Authenticate(env.backgroundCtx, &svc.AuthenticateRequest{
		Username: registerReq.Username,
		Password: registerReq.Password,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	snapshotResp, err := env.userService.GetAuthSnapshot(env.backgroundCtx, user.GetID())
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

	assertContains(authResp.Roles, "role_active", "auth roles")
	assertNotContains(authResp.Roles, "role_inactive", "auth roles")
	assertNotContains(authResp.Roles, "role_deleted", "auth roles")
	assertContains(authResp.Permissions, "perm:active", "auth permissions")
	assertNotContains(authResp.Permissions, "perm:inactive", "auth permissions")
	assertNotContains(authResp.Permissions, "perm:deleted", "auth permissions")

	assertContains(snapshotResp.Roles, "role_active", "snapshot roles")
	assertNotContains(snapshotResp.Roles, "role_inactive", "snapshot roles")
	assertNotContains(snapshotResp.Roles, "role_deleted", "snapshot roles")
	assertContains(snapshotResp.Permissions, "perm:active", "snapshot permissions")
	assertNotContains(snapshotResp.Permissions, "perm:inactive", "snapshot permissions")
	assertNotContains(snapshotResp.Permissions, "perm:deleted", "snapshot permissions")

	perms, err := env.userService.GetUserPermissions(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user permissions: %v", err)
	}
	assertContains(perms, "perm:active", "user permissions")
	assertNotContains(perms, "perm:inactive", "user permissions")
	assertNotContains(perms, "perm:deleted", "user permissions")

	allowed, err := env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:active")
	if err != nil {
		t.Fatalf("check permission perm:active: %v", err)
	}
	if !allowed {
		t.Fatalf("expected perm:active allowed")
	}
	allowed, err = env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:inactive")
	if err != nil {
		t.Fatalf("check permission perm:inactive: %v", err)
	}
	if allowed {
		t.Fatalf("expected perm:inactive denied")
	}
	allowed, err = env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:deleted")
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

	role := env.createTestRole(t, "perm_role", []string{"perm:active"})

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
			user, err := env.userService.Register(env.backgroundCtx, registerReq)
			if err != nil {
				t.Fatalf("register user: %v", err)
			}

			if err := env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID()); err != nil {
				t.Fatalf("assign role: %v", err)
			}

			if err := tt.disable(env.backgroundCtx, user.GetID()); err != nil {
				t.Fatalf("disable user (%s): %v", tt.name, err)
			}

			perms, err := env.userService.GetUserPermissions(env.backgroundCtx, user.GetID())
			if err == nil {
				t.Fatalf("expected error for %s user, got perms %v", tt.name, perms)
			}
			if !errorx.Is(err, errorx.Forbidden) {
				t.Fatalf("expected forbidden error for %s user, got %v", tt.name, err)
			}

			allowed, err := env.userService.CheckPermission(env.backgroundCtx, user.GetID(), "perm:active")
			if err == nil {
				t.Fatalf("expected error for %s user, got allowed=%v", tt.name, allowed)
			}
			if !errorx.Is(err, errorx.Forbidden) {
				t.Fatalf("expected forbidden error for %s user, got %v", tt.name, err)
			}
			if allowed {
				t.Fatalf("expected allowed=false for %s user", tt.name)
			}
		})
	}
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
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
	_, err = env.userService.Authenticate(env.backgroundCtx, loginReq)
	if err == nil {
		t.Error("expected login to fail with old password")
	}

	// 验证新密码可以登录
	loginReq.Password = "newpassword123"
	resp, err := env.userService.Authenticate(env.backgroundCtx, loginReq)
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 停用用户
	err = env.userService.DeactivateUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("deactivate user: %v", err)
	}

	// 验证状态
	dbUser, err := env.userRepo.GetByID(env.backgroundCtx, user.GetID())
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
	dbUser, err = env.userRepo.GetByID(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if dbUser.Status != svc.UserStatusActive {
		t.Errorf("expected status %s, got %s", svc.UserStatusActive, dbUser.Status)
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 锁定用户
	err = env.userService.LockUser(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("lock user: %v", err)
	}

	// 验证状态
	dbUser, err := env.userRepo.GetByID(env.backgroundCtx, user.GetID())
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
	dbUser, err = env.userRepo.GetByID(env.backgroundCtx, user.GetID())
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建角色
	role := env.createTestRole(t, "test_role", []string{"test:read", "test:write"})

	// 分配角色
	err = env.userService.AssignRole(env.backgroundCtx, user.GetID(), role.GetID())
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}

	// 验证角色
	roles, err := env.userService.GetUserRoles(env.backgroundCtx, user.GetID())
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
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
	groups, err := env.userService.GetUserGroups(env.backgroundCtx, user.GetID())
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	// 创建并分配角色
	role := env.createTestRole(t, "remove_role", []string{"test:read"})
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
	roles, err := env.userService.GetUserRoles(env.backgroundCtx, user.GetID())
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
	user, err := env.userService.Register(env.backgroundCtx, registerReq)
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
	groups, err := env.userService.GetUserGroups(env.backgroundCtx, user.GetID())
	if err != nil {
		t.Fatalf("get user groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}
