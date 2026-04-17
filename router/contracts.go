package router

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	menusvc "gochen-iam/service/menu"
	"gochen/httpx"
)

// IUserService 定义用户服务能力接口。
type IUserService interface {
	Register(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error)
	Authenticate(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error)
	ActivateScope(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error)
	AuthSnapshot(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error)
	ChangePassword(ctx context.Context, userID int64, req *svc.ChangePasswordRequest) error
	UpdateProfile(ctx context.Context, userID int64, req *svc.UpdateUserRequest) (*iamentity.User, error)
	ActivateUser(ctx context.Context, userID int64) error
	DeactivateUser(ctx context.Context, userID int64) error
	LockUser(ctx context.Context, userID int64) error
	UnlockUser(ctx context.Context, userID int64) error
	AssignRole(ctx context.Context, userID, roleID int64) error
	RemoveRole(ctx context.Context, userID, roleID int64) error
	AssignToGroup(ctx context.Context, userID, groupID int64) error
	RemoveFromGroup(ctx context.Context, userID, groupID int64) error
	UserPermissions(ctx context.Context, userID int64) ([]string, error)
	CheckPermission(ctx context.Context, userID int64, permission string) (bool, error)
	UserRoles(ctx context.Context, userID int64) ([]*iamentity.Role, error)
	UserGroups(ctx context.Context, userID int64) ([]*iamentity.Group, error)
	UserProfile(ctx context.Context, userID int64) (*iamentity.User, error)
}

// IGroupService 定义分组服务能力接口。
type IGroupService interface {
	GroupTree(ctx context.Context) ([]*svc.GroupTreeNode, error)
	RootGroups(ctx context.Context, tenantID string) ([]*iamentity.Group, error)
	GroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error)
	GroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error)
	AddUserToGroup(ctx context.Context, groupID, userID int64) error
	RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error
	BatchAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error)
	GroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error)
	AddGroupRole(ctx context.Context, groupID, roleID int64) error
	RemoveGroupRole(ctx context.Context, groupID, roleID int64) error
	GroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error)
}

// IRoleService 定义角色服务能力接口。
type IRoleService interface {
	AddPermission(ctx context.Context, roleID int64, permission string) error
	RemovePermission(ctx context.Context, roleID int64, permission string) error
	RoleUsers(ctx context.Context, roleID int64) ([]*iamentity.User, error)
	BatchAssignRole(ctx context.Context, req *svc.RoleAssignRequest) (*svc.BatchOperationResponse, error)
	RemoveRoleFromUser(ctx context.Context, roleID, userID int64) error
	ActivateRole(ctx context.Context, roleID int64) error
	DeactivateRole(ctx context.Context, roleID int64) error
	CloneRole(ctx context.Context, roleID int64, newName string) (*iamentity.Role, error)
	SystemRoles(ctx context.Context) ([]*iamentity.Role, error)
	InitializeSystemRoles(ctx context.Context, tenantID string) error
	RoleStatistics(ctx context.Context) (map[string]interface{}, error)
}

// ITenantService 定义租户服务能力接口。
type ITenantService interface {
	ActivateTenant(ctx context.Context, tenantID int64) error
	DeactivateTenant(ctx context.Context, tenantID int64) error
}

// IMenuService 定义菜单服务能力接口。
type IMenuService interface {
	CreateMenuItem(ctx context.Context, req *menusvc.CreateMenuItemRequest) (*iamentity.MenuItem, error)
	UpdateMenuItem(ctx context.Context, id int64, req *menusvc.UpdateMenuItemRequest, patches ...svc.FieldPatch[iamentity.MenuItem]) (*iamentity.MenuItem, error)
	SyncMenuItems(ctx context.Context, req *menusvc.SyncMenuItemsRequest) (*menusvc.SyncMenuItemsResult, error)
	DeleteMenuItem(ctx context.Context, id int64) error
	RestoreMenuItem(ctx context.Context, id int64) (*iamentity.MenuItem, error)
	PurgeMenuItem(ctx context.Context, id int64) error
	PublishMenuItem(ctx context.Context, id int64, published bool) (*iamentity.MenuItem, error)
	ListMenuItems(ctx context.Context) ([]*iamentity.MenuItem, error)
	MyMenuTree(ctx context.Context, reqCtx httpx.IRequestContext) ([]*menusvc.MenuNode, error)
}
