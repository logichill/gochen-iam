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
}

// setupGroupServiceTest 设置测试环境
func setupGroupServiceTest(t *testing.T) *groupServiceTestEnv {
	// 创建临时目录
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "group_test.db")

	// 配置环境变量
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DATABASE", dbPath)

	// 打开数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	ormAdapter := newGroupTestOrm(db)

	// 自动迁移表结构
	if err := db.AutoMigrate(
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

	// 创建服务
	groupService := groupsvc.NewGroupService(groupRepo, userRepo, roleRepo)
	userService := usersvc.NewUserService(userRepo, groupRepo, roleRepo)

	// 创建背景上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	return &groupServiceTestEnv{
		db:            db,
		groupService:  groupService,
		userService:   userService,
		groupRepo:     groupRepo,
		userRepo:      userRepo,
		roleRepo:      roleRepo,
		backgroundCtx: ctx,
		cancelFunc:    cancel,
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
	user, err := env.userService.Register(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user
}

// createTestRole 创建测试角色
func (env *groupServiceTestEnv) createTestRole(t *testing.T, name string) *iamentity.Role {
	role := &iamentity.Role{
		Name:        name,
		Description: "测试角色",
		Permissions: iamentity.PermissionArray([]string{"test:read"}),
		Status:      svc.RoleStatusActive,
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
		Name:        "测试组织",
		Description: "第一个",
	}
	_, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create first group: %v", err)
	}

	// 尝试创建同名组织
	req2 := &svc.CreateGroupRequest{
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

// TestGroupServiceDeleteGroup 测试删除组织
func TestGroupServiceDeleteGroup(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// 创建组织
	req := &svc.CreateGroupRequest{
		Name:        "待删除组织",
		Description: "这个组织将被删除",
	}
	group, err := env.groupService.CreateGroup(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// 删除组织
	err = env.groupService.DeleteGroup(env.backgroundCtx, group.GetID())
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}

	// 验证已删除
	_, err = env.groupRepo.GetByID(env.backgroundCtx, group.GetID())
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
	users, err := env.groupService.GetGroupUsers(env.backgroundCtx, group.GetID())
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
	users, err := env.groupService.GetGroupUsers(env.backgroundCtx, group.GetID())
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
	users, err := env.groupService.GetGroupUsers(env.backgroundCtx, group.GetID())
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
	roles, err := env.groupService.GetGroupRoles(env.backgroundCtx, group.GetID())
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
		Name:        "根组织1",
		Description: "第一个根组织",
	}
	_, err := env.groupService.CreateGroup(env.backgroundCtx, req1)
	if err != nil {
		t.Fatalf("create root group 1: %v", err)
	}

	req2 := &svc.CreateGroupRequest{
		Name:        "根组织2",
		Description: "第二个根组织",
	}
	_, err = env.groupService.CreateGroup(env.backgroundCtx, req2)
	if err != nil {
		t.Fatalf("create root group 2: %v", err)
	}

	// 获取根组织
	rootGroups, err := env.groupService.GetRootGroups(env.backgroundCtx)
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
	level2Groups, err := env.groupService.GetGroupsByLevel(env.backgroundCtx, 2)
	if err != nil {
		t.Fatalf("get level 2 groups: %v", err)
	}
	if len(level2Groups) != 2 {
		t.Errorf("expected 2 level 2 groups, got %d", len(level2Groups))
	}
}
