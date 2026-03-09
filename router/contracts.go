package router

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	menusvc "gochen-iam/service/menu"
	"gochen/httpx"
)

type userService interface {
	Register(ctx context.Context, req *svc.RegisterRequest) (*iamentity.User, error)
	Authenticate(ctx context.Context, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error)
	GetAuthSnapshot(ctx context.Context, userID int64) (*svc.AuthenticateResult, error)
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
	GetUserPermissions(ctx context.Context, userID int64) ([]string, error)
	CheckPermission(ctx context.Context, userID int64, permission string) (bool, error)
	GetUserRoles(ctx context.Context, userID int64) ([]*iamentity.Role, error)
	GetUserGroups(ctx context.Context, userID int64) ([]*iamentity.Group, error)
	GetUserProfile(ctx context.Context, userID int64) (*iamentity.User, error)
}

type groupService interface {
	GetGroupTree(ctx context.Context) ([]*svc.GroupTreeNode, error)
	GetRootGroups(ctx context.Context) ([]*iamentity.Group, error)
	GetGroupsByLevel(ctx context.Context, level int) ([]*iamentity.Group, error)
	GetGroupUsers(ctx context.Context, groupID int64) ([]*iamentity.User, error)
	AddUserToGroup(ctx context.Context, groupID, userID int64) error
	RemoveUserFromGroup(ctx context.Context, groupID, userID int64) error
	BatchAddUsersToGroup(ctx context.Context, groupID int64, userIDs []int64) (*svc.BatchOperationResponse, error)
	GetGroupRoles(ctx context.Context, groupID int64) ([]*iamentity.Role, error)
	AddGroupRole(ctx context.Context, groupID, roleID int64) error
	RemoveGroupRole(ctx context.Context, groupID, roleID int64) error
	GetGroupStatistics(ctx context.Context) (*svc.StatisticsResponse, error)
}

type roleService interface {
	AddPermission(ctx context.Context, roleID int64, permission string) error
	RemovePermission(ctx context.Context, roleID int64, permission string) error
	GetRoleUsers(ctx context.Context, roleID int64) ([]*iamentity.User, error)
	BatchAssignRole(ctx context.Context, req *svc.RoleAssignRequest) (*svc.BatchOperationResponse, error)
	RemoveRoleFromUser(ctx context.Context, roleID, userID int64) error
	ActivateRole(ctx context.Context, roleID int64) error
	DeactivateRole(ctx context.Context, roleID int64) error
	CloneRole(ctx context.Context, roleID int64, newName string) (*iamentity.Role, error)
	GetSystemRoles(ctx context.Context) ([]*iamentity.Role, error)
	InitializeSystemRoles(ctx context.Context) error
	GetRoleStatistics(ctx context.Context) (map[string]interface{}, error)
}

type tenantService interface {
	ActivateTenant(ctx context.Context, tenantID int64) error
	DeactivateTenant(ctx context.Context, tenantID int64) error
}

type menuService interface {
	CreateMenuItem(ctx context.Context, req *menusvc.CreateMenuItemRequest) (*iamentity.MenuItem, error)
	UpdateMenuItem(ctx context.Context, id int64, req *menusvc.UpdateMenuItemRequest) (*iamentity.MenuItem, error)
	DeleteMenuItem(ctx context.Context, id int64) error
	RestoreMenuItem(ctx context.Context, id int64) (*iamentity.MenuItem, error)
	PurgeMenuItem(ctx context.Context, id int64) error
	PublishMenuItem(ctx context.Context, id int64, published bool) (*iamentity.MenuItem, error)
	ListMenuItems(ctx context.Context) ([]*iamentity.MenuItem, error)
	GetMyMenuTree(ctx context.Context, reqCtx httpx.IRequestContext) ([]*menusvc.MenuNode, error)
}
