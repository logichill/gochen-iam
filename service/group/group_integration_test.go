package group_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	usersvc "gochen-iam/service/user"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/errorx"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// groupServiceTestEnv 组织服务测试环境
type groupServiceTestEnv struct {
	db            *gorm.DB
	groupService  *groupsvc.GroupService
	userService   *usersvc.UserService
	groupRepo     *grouprepo.GroupRepo
	userRepo      *userrepo.UserRepo
	roleRepo      *rolerepo.RoleRepo
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
	tenantID      string
}

// setupGroupServiceTest 设置测试环境
func setupGroupServiceTest(t *testing.T) *groupServiceTestEnv {
	// 创建临时目录
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "group_test.db")

	// 配置环境变量
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)
	t.Setenv("IAM_TENANT_MODE", "tenant") // 测试使用 tenant 模式

	// 打开数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ormAdapter := newGroupTestOrm(db)
	if err := iamentity.SetupJoinTables(db); err != nil {
		t.Fatalf("setup join tables: %v", err)
	}

	// 自动迁移表结构
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

	// 创建仓储
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
	authorizer, err := svc.NewIAMAuthorizer(nil)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	// 创建服务
	groupService := groupsvc.NewGroupService(groupRepo, userRepo, roleRepo, nil, authorizer)
	userService := usersvc.NewUserService(userRepo, groupRepo, roleRepo, nil, authorizer)

	// 创建背景上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, err = authz.WithPrincipal(ctx, authz.Principal{
		SubjectID:     1,
		Permissions:   []string{"*:*:*"},
		ActiveScopeID: 1,
		IsSystem:      true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = ctxx.WithTenantID(ctx, "test-tenant")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	return &groupServiceTestEnv{
		db:            db,
		groupService:  groupService,
		userService:   userService,
		groupRepo:     groupRepo,
		userRepo:      userRepo,
		roleRepo:      roleRepo,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
		tenantID:      "test-tenant",
	}
}

// teardown 清理测试环境
func (env *groupServiceTestEnv) teardown(t *testing.T) {
	env.cancelFunc()

	sqlDB, err := env.db.DB()
	if err == nil {
		sqlDB.Close()
	}
}

// createTestUser 创建测试用户
func (env *groupServiceTestEnv) createTestUser(t *testing.T, username, email string) *iamentity.User {
	req := &svc.RegisterRequest{

		Username: username,
		Email:    email,
		Password: "password123",
	}
	user, err := env.userService.Register(env.backgroundCtx, env.tenantID, req)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user
}

// createTestRole 创建测试角色
func (env *groupServiceTestEnv) createTestRole(t *testing.T, name string) *iamentity.Role {
	role := &iamentity.Role{
		TenantID:         "test-tenant",
		NamespaceScopeID: 1,
		Name:             name,
		Description:      "测试角色",
		Permissions:      iamentity.PermissionArray([]string{"api:test:read"}),
		Status:           svc.RoleStatusActive,
	}
	if err := env.roleRepo.Create(env.backgroundCtx, role); err != nil {
		t.Fatalf("create test role: %v", err)
	}
	return role
}

// TestGroupServiceCreateGroup 测试创建组织
func TestGroupServiceCreateGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建根组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织",
		Description: "这是一个根组织",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create root group: %v", err)
	}

	if group.Name != req.Name {
		t.Errorf("expected name %s, got %s", req.Name, group.Name)
	}
	if group.Level != 1 {
		t.Errorf("expected level 1, got %d", group.Level)
	}
	if group.ParentID != nil {
		t.Errorf("expected nil parent ID, got %v", *group.ParentID)
	}
	if group.Path != "/"+strconv.FormatInt(group.GetID(), 10) {
		t.Errorf("expected path /%d, got %s", group.GetID(), group.Path)
	}

	// 创建子组织
	parentID := group.GetID()
	childReq := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "子组织",
		Description: "这是一个子组织",
		ParentID:    &parentID,
	}
	childGroup, err := env.groupService.CreateGroup(env.backgroundCtx, childReq)
	if err != nil {
		t.Fatalf("create child group: %v", err)
	}

	if childGroup.Level != 2 {
		t.Errorf("expected level 2, got %d", childGroup.Level)
	}
	if childGroup.ParentID == nil || *childGroup.ParentID != parentID {
		t.Errorf("expected parent ID %d, got %v", parentID, childGroup.ParentID)
	}
	expectedChildPath := group.Path + "/" + strconv.FormatInt(childGroup.GetID(), 10)
	if childGroup.Path != expectedChildPath {
		t.Errorf("expected child path %s, got %s", expectedChildPath, childGroup.Path)
	}
}

// TestGroupServiceCreateDuplicateName 测试创建重名组织
func TestGroupServiceCreateDuplicateName(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建第一个组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "测试组织",
		Description: "第一个",
	}
	_, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create first group: %v", err)
	}

	// 尝试创建同名组织
	req2 := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "测试组织",
		Description: "第二个",
	}
	_, err = env.groupService.CreateGroup(env.backgroundCtx, req2)
	if err == nil {
		t.Error("expected error for duplicate name, got nil")
	}
	if appErr, ok := err.(*errorx.AppError); ok {
		if appErr.Code() != errorx.Validation {
			t.Errorf("expected validation error, got %s", appErr.Code())
		}
	}
}

// TestGroupServiceUpdateGroup 测试更新组织
func TestGroupServiceUpdateGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "原组织名",
		Description: "原描述",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 更新组织
	updateReq := &svc.UpdateGroupRequest{
		Name:        "新组织名",
		Description: "新描述",
	}
	updatedGroup, err := env.groupService.UpdateGroup(env.backgroundCtx, group.GetID(), updateReq)
	if err != nil {
		t.Fatalf("update group: %v", err)
	}

	if updatedGroup.Name != updateReq.Name {
		t.Errorf("expected name %s, got %s", updateReq.Name, updatedGroup.Name)
	}
	if updatedGroup.Description != updateReq.Description {
		t.Errorf("expected description %s, got %s", updateReq.Description, updatedGroup.Description)
	}
}

func TestGroupServiceUpdateGroup_KeepParentWhenParentIDOmitted(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	root, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织",
		Description: "root",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootID := root.GetID()

	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "子组织",
		Description: "child",
		ParentID:    &rootID,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	updated, err := env.groupService.UpdateGroup(env.backgroundCtx, child.GetID(), &svc.UpdateGroupRequest{
		Name: "子组织-改名",
	})
	if err != nil {
		t.Fatalf("update child name: %v", err)
	}
	if updated.ParentID == nil || *updated.ParentID != rootID {
		t.Fatalf("expected parent to stay %d, got %v", rootID, updated.ParentID)
	}
	expectedPath := root.Path + "/" + strconv.FormatInt(child.GetID(), 10)
	if updated.Path != expectedPath {
		t.Fatalf("expected path %s, got %s", expectedPath, updated.Path)
	}
	if updated.Level != 2 {
		t.Fatalf("expected level 2, got %d", updated.Level)
	}
}

func TestGroupServiceUpdateGroup_UnsetParentWithExplicitNil(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	root, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织",
		Description: "root",
	})
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootID := root.GetID()

	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "子组织",
		Description: "child",
		ParentID:    &rootID,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	updated, err := env.groupService.UpdateGroup(
		env.backgroundCtx,
		child.GetID(),
		&svc.UpdateGroupRequest{},
		svc.ValueFieldPatch(func(group *iamentity.Group, parentID *int64) {
			group.ParentID = parentID
		}, (*int64)(nil)),
		svc.ValueFieldPatch(func(group *iamentity.Group, description string) {
			group.Description = description
		}, ""),
	)
	if err != nil {
		t.Fatalf("unset child parent: %v", err)
	}
	if updated.ParentID != nil {
		t.Fatalf("expected parent to be cleared, got %v", updated.ParentID)
	}
	if updated.Level != 1 {
		t.Fatalf("expected level 1, got %d", updated.Level)
	}
	expectedPath := "/" + strconv.FormatInt(child.GetID(), 10)
	if updated.Path != expectedPath {
		t.Fatalf("expected path %s, got %s", expectedPath, updated.Path)
	}
	if updated.Description != "" {
		t.Fatalf("expected description cleared, got %q", updated.Description)
	}
}

func TestGroupServiceUpdateGroup_ReparentsDescendants(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	rootA, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织A",
		Description: "A",
	})
	if err != nil {
		t.Fatalf("create rootA: %v", err)
	}
	rootB, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织B",
		Description: "B",
	})
	if err != nil {
		t.Fatalf("create rootB: %v", err)
	}

	rootAID := rootA.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "子组织",
		Description: "child",
		ParentID:    &rootAID,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	childID := child.GetID()
	grand, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "孙组织",
		Description: "grand",
		ParentID:    &childID,
	})
	if err != nil {
		t.Fatalf("create grand: %v", err)
	}

	rootBID := rootB.GetID()
	updatedChild, err := env.groupService.UpdateGroup(
		env.backgroundCtx,
		child.GetID(),
		&svc.UpdateGroupRequest{},
		svc.ValueFieldPatch(func(group *iamentity.Group, parentID *int64) {
			group.ParentID = parentID
		}, &rootBID),
	)
	if err != nil {
		t.Fatalf("reparent child: %v", err)
	}

	expectedChildPath := rootB.Path + "/" + strconv.FormatInt(child.GetID(), 10)
	if updatedChild.Path != expectedChildPath {
		t.Fatalf("expected child path %s, got %s", expectedChildPath, updatedChild.Path)
	}

	storedGrand, err := env.groupRepo.Get(env.backgroundCtx, grand.GetID())
	if err != nil {
		t.Fatalf("get grand after reparent: %v", err)
	}
	expectedGrandPath := expectedChildPath + "/" + strconv.FormatInt(grand.GetID(), 10)
	if storedGrand.Path != expectedGrandPath {
		t.Fatalf("expected grand path %s, got %s", expectedGrandPath, storedGrand.Path)
	}
	if storedGrand.Level != 3 {
		t.Fatalf("expected grand level 3, got %d", storedGrand.Level)
	}
}

func TestGroupServiceUpdateGroup_RejectsDuplicateNameInTargetParent(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	rootA, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织A",
		Description: "A",
	})
	if err != nil {
		t.Fatalf("create rootA: %v", err)
	}
	rootB, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织B",
		Description: "B",
	})
	if err != nil {
		t.Fatalf("create rootB: %v", err)
	}

	rootAID := rootA.GetID()
	rootBID := rootB.GetID()
	if _, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "共享名称",
		Description: "target sibling",
		ParentID:    &rootAID,
	}); err != nil {
		t.Fatalf("create target sibling: %v", err)
	}
	moving, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "共享名称",
		Description: "moving child",
		ParentID:    &rootBID,
	})
	if err != nil {
		t.Fatalf("create moving child: %v", err)
	}

	_, err = env.groupService.UpdateGroup(
		env.backgroundCtx,
		moving.GetID(),
		&svc.UpdateGroupRequest{},
		svc.ValueFieldPatch(func(group *iamentity.Group, parentID *int64) {
			group.ParentID = parentID
		}, &rootAID),
	)
	if err == nil {
		t.Fatalf("expected duplicate name validation when reparenting into target parent")
	}
	if !errorx.Is(err, errorx.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

// TestGroupServiceDeleteGroup 测试删除组织
func TestGroupServiceDeleteGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "待删除组织",
		Description: "这个组织将被删除",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 删除组织
	err = env.groupService.DeleteGroup(env.backgroundCtx, env.tenantID, group.GetID())
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}

	// 验证已删除
	_, err = env.groupRepo.Get(env.backgroundCtx, group.GetID())
	if err == nil {
		t.Error("expected error when getting deleted group, got nil")
	}
}

// TestGroupServiceAddUserToGroup 测试添加用户到组织
func TestGroupServiceAddUserToGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "测试组织",
		Description: "添加用户测试",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 创建用户
	user := env.createTestUser(t, "groupuser", "groupuser@example.com")

	// 添加用户到组织
	err = env.groupService.AddUserToGroup(env.backgroundCtx, group.GetID(), user.GetID())
	if err != nil {
		t.Fatalf("add user to group: %v", err)
	}

	// 验证用户已加入
	users, err := env.groupService.GroupUsers(env.backgroundCtx, group.GetID())
	if err != nil {
		t.Fatalf("get group users: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}
	if len(users) > 0 && users[0].Username != "groupuser" {
		t.Errorf("expected username groupuser, got %s", users[0].Username)
	}
}

// TestGroupServiceRemoveUserFromGroup 测试从组织移除用户
func TestGroupServiceRemoveUserFromGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "移除测试组织",
		Description: "移除用户测试",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 创建并添加用户
	user := env.createTestUser(t, "removeuser", "removeuser@example.com")
	err = env.groupService.AddUserToGroup(env.backgroundCtx, group.GetID(), user.GetID())
	if err != nil {
		t.Fatalf("add user to group: %v", err)
	}

	// 移除用户
	err = env.groupService.RemoveUserFromGroup(env.backgroundCtx, group.GetID(), user.GetID())
	if err != nil {
		t.Fatalf("remove user from group: %v", err)
	}

	// 验证用户已移除
	users, err := env.groupService.GroupUsers(env.backgroundCtx, group.GetID())
	if err != nil {
		t.Fatalf("get group users: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

// TestGroupServiceBatchAddUsersToGroup 测试批量添加用户
func TestGroupServiceBatchAddUsersToGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "批量添加测试",
		Description: "批量添加用户测试",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 创建多个用户
	user1 := env.createTestUser(t, "batchuser1", "batch1@example.com")
	user2 := env.createTestUser(t, "batchuser2", "batch2@example.com")
	user3 := env.createTestUser(t, "batchuser3", "batch3@example.com")

	// 批量添加
	userIDs := []int64{user1.GetID(), user2.GetID(), user3.GetID()}
	resp, err := env.groupService.BatchAddUsersToGroup(env.backgroundCtx, group.GetID(), userIDs)
	if err != nil {
		t.Fatalf("batch add users: %v", err)
	}

	if resp.SuccessCount != 3 {
		t.Errorf("expected success count 3, got %d", resp.SuccessCount)
	}
	if resp.FailureCount != 0 {
		t.Errorf("expected failure count 0, got %d", resp.FailureCount)
	}

	// 验证所有用户已加入
	users, err := env.groupService.GroupUsers(env.backgroundCtx, group.GetID())
	if err != nil {
		t.Fatalf("get group users: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users, got %d", len(users))
	}
}

// TestGroupServiceAddGroupRole 测试添加组织角色
func TestGroupServiceAddGroupRole(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "角色测试组织",
		Description: "角色测试",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 创建角色
	role := env.createTestRole(t, "group_role")

	// 添加角色到组织
	err = env.groupService.AddGroupRole(env.backgroundCtx, group.GetID(), role.GetID())
	if err != nil {
		t.Fatalf("add group role: %v", err)
	}

	// 验证角色已添加
	roles, err := env.groupService.GroupRoles(env.backgroundCtx, group.GetID())
	if err != nil {
		t.Fatalf("get group roles: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("expected 1 role, got %d", len(roles))
	}
	if len(roles) > 0 && roles[0].Name != "group_role" {
		t.Errorf("expected role name group_role, got %s", roles[0].Name)
	}
}

// TestGroupServiceGetRootGroups 测试获取根组织
func TestGroupServiceGetRootGroups(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建两个根组织
	req1 := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织1",
		Description: "第一个根组织",
	}
	_, err := env.groupService.CreateGroup(env.backgroundCtx, req1)
	if err != nil {
		t.Fatalf("create root group 1: %v", err)
	}

	req2 := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织2",
		Description: "第二个根组织",
	}
	_, err = env.groupService.CreateGroup(env.backgroundCtx, req2)
	if err != nil {
		t.Fatalf("create root group 2: %v", err)
	}

	// 获取根组织
	rootGroups, err := env.groupService.RootGroups(env.backgroundCtx, env.tenantID)
	if err != nil {
		t.Fatalf("get root groups: %v", err)
	}
	if len(rootGroups) != 2 {
		t.Errorf("expected 2 root groups, got %d", len(rootGroups))
	}
}

// TestGroupServiceGetGroupsByLevel 测试按层级获取组织
func TestGroupServiceGetGroupsByLevel(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建根组织
	rootReq := &svc.CreateGroupRequest{

		TenantID:    env.tenantID,
		Name:        "根组织",
		Description: "根组织",
	}
	rootGroup, err := env.groupService.CreateGroup(env.backgroundCtx, rootReq)
	if err != nil {
		t.Fatalf("create root group: %v", err)
	}

	// 创建两个二级组织
	parentID := rootGroup.GetID()
	for i := 1; i <= 2; i++ {
		childReq := &svc.CreateGroupRequest{
			TenantID:    env.tenantID,
			Name:        "二级组织" + string(rune('0'+i)),
			Description: "二级",
			ParentID:    &parentID,
		}
		_, err := env.groupService.CreateGroup(env.backgroundCtx, childReq)
		if err != nil {
			t.Fatalf("create level 2 group %d: %v", i, err)
		}
	}

	// 获取二级组织
	level2Groups, err := env.groupService.GroupsByLevel(env.backgroundCtx, 2)
	if err != nil {
		t.Fatalf("get level 2 groups: %v", err)
	}
	if len(level2Groups) != 2 {
		t.Errorf("expected 2 level 2 groups, got %d", len(level2Groups))
	}
}

func TestGroupServiceGetGroupTree_IsTenantScoped(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	if _, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        "tenant-a-root",
		Description: "tenant a",
	}); err != nil {
		t.Fatalf("create tenant-a root: %v", err)
	}

	otherCtx, err := svc.BindTenantContext(env.backgroundCtx, "other-tenant")
	if err != nil {
		t.Fatalf("BindTenantContext(other): %v", err)
	}
	otherCtx, err = svc.BindManagedScopeContext(otherCtx, 1)
	if err != nil {
		t.Fatalf("BindManagedScopeContext(other): %v", err)
	}
	if _, err := env.groupService.CreateGroup(otherCtx, &svc.CreateGroupRequest{
		TenantID:    "other-tenant",
		Name:        "tenant-b-root",
		Description: "tenant b",
	}); err != nil {
		t.Fatalf("create tenant-b root: %v", err)
	}

	tree, err := env.groupService.GroupTree(env.backgroundCtx)
	if err != nil {
		t.Fatalf("GroupTree: %v", err)
	}
	if len(tree) != 1 {
		t.Fatalf("expected 1 root node for tenant %s, got %d", env.tenantID, len(tree))
	}
	if tree[0].Name != "tenant-a-root" {
		t.Fatalf("expected tenant-a tree only, got %s", tree[0].Name)
	}
}

func TestGroupRepoCreateRejectsDuplicateRootGroupPerTenant(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	first := &iamentity.Group{TenantID: env.tenantID, Name: "root"}
	if err := env.groupRepo.Create(env.backgroundCtx, first); err != nil {
		t.Fatalf("create first root group: %v", err)
	}

	second := &iamentity.Group{TenantID: env.tenantID, Name: "root"}
	if err := env.groupRepo.Create(env.backgroundCtx, second); err == nil {
		t.Fatalf("expected duplicate root group to be rejected")
	}
}

func TestGroupRepoCreateSyncsHierarchyFromParentID(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	parent, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        "root",
		Description: "root",
	})
	if err != nil {
		t.Fatalf("create parent group: %v", err)
	}

	parentID := parent.GetID()
	child := &iamentity.Group{
		TenantID: env.tenantID,
		Name:     "child",
		ParentID: &parentID,
	}
	if err := env.groupRepo.Create(env.backgroundCtx, child); err != nil {
		t.Fatalf("create child group via repo: %v", err)
	}

	if child.ParentKey != parentID {
		t.Fatalf("expected parent_key %d, got %d", parentID, child.ParentKey)
	}
	if child.Level != 2 {
		t.Fatalf("expected level 2, got %d", child.Level)
	}
	wantPath := parent.Path + "/" + strconv.FormatInt(child.GetID(), 10)
	if child.Path != wantPath {
		t.Fatalf("expected path %s, got %s", wantPath, child.Path)
	}
}

func TestGroupRepoUpdateSyncsHierarchyFromParentID(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	rootA, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        "root-a",
		Description: "root a",
	})
	if err != nil {
		t.Fatalf("create root-a: %v", err)
	}
	rootB, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        "root-b",
		Description: "root b",
	})
	if err != nil {
		t.Fatalf("create root-b: %v", err)
	}

	rootAID := rootA.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
		TenantID:    env.tenantID,
		Name:        "child",
		Description: "child",
		ParentID:    &rootAID,
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	rootBID := rootB.GetID()
	child.Parent = nil
	child.ParentID = &rootBID
	if err := env.groupRepo.Update(env.backgroundCtx, child); err != nil {
		t.Fatalf("update child via repo: %v", err)
	}

	if child.ParentKey != rootBID {
		t.Fatalf("expected parent_key %d, got %d", rootBID, child.ParentKey)
	}
	if child.Level != 2 {
		t.Fatalf("expected level 2, got %d", child.Level)
	}
	wantPath := rootB.Path + "/" + strconv.FormatInt(child.GetID(), 10)
	if child.Path != wantPath {
		t.Fatalf("expected path %s, got %s", wantPath, child.Path)
	}
}
