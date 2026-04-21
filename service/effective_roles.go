package service

import (
	"context"
	"sort"
	"strings"

	iamentity "gochen-iam/entity"
)

type effectiveUserRoleRepo interface {
	FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Role, error)
	FindByGroupID(ctx context.Context, groupID int64) ([]*iamentity.Role, error)
}

type effectiveUserGroupRepo interface {
	FindByUserID(ctx context.Context, userID int64) ([]*iamentity.Group, error)
}

// ResolveEffectiveRolesForUser 返回用户的有效角色：
// 1. 直接绑定角色
// 2. 所属 group 的默认角色
func ResolveEffectiveRolesForUser(
	ctx context.Context,
	userID int64,
	roleRepo effectiveUserRoleRepo,
	groupRepo effectiveUserGroupRepo,
) ([]*iamentity.Role, error) {
	directRoles, err := roleRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	roleSet := make(map[int64]*iamentity.Role, len(directRoles))
	for _, role := range directRoles {
		if role == nil || role.GetID() <= 0 {
			continue
		}
		roleSet[role.GetID()] = role
	}

	groups, err := groupRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if group == nil || group.GetID() <= 0 {
			continue
		}
		groupRoles, err := roleRepo.FindByGroupID(ctx, group.GetID())
		if err != nil {
			return nil, err
		}
		for _, role := range groupRoles {
			if role == nil || role.GetID() <= 0 {
				continue
			}
			roleSet[role.GetID()] = role
		}
	}

	roles := make([]*iamentity.Role, 0, len(roleSet))
	for _, role := range roleSet {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].GetID() < roles[j].GetID()
	})
	return roles, nil
}

// ResolveEffectiveRoleNamesAndPermissionsForUser 返回用户有效角色名与权限集合。
func ResolveEffectiveRoleNamesAndPermissionsForUser(
	ctx context.Context,
	userID int64,
	roleRepo effectiveUserRoleRepo,
	groupRepo effectiveUserGroupRepo,
) ([]string, []string, error) {
	roles, err := ResolveEffectiveRolesForUser(ctx, userID, roleRepo, groupRepo)
	if err != nil {
		return nil, nil, err
	}

	roleNames := make([]string, 0, len(roles))
	roleSet := make(map[string]struct{}, len(roles))
	permissions := make([]string, 0)
	permissionSet := make(map[string]struct{})

	for _, role := range roles {
		if role == nil || !role.IsActive() {
			continue
		}
		name := strings.TrimSpace(role.Name)
		if name != "" {
			if _, exists := roleSet[name]; !exists {
				roleSet[name] = struct{}{}
				roleNames = append(roleNames, name)
			}
		}
		for _, permission := range role.Permissions {
			permission = strings.TrimSpace(permission)
			if permission == "" {
				continue
			}
			if _, exists := permissionSet[permission]; !exists {
				permissionSet[permission] = struct{}{}
				permissions = append(permissions, permission)
			}
		}
	}

	sort.Strings(roleNames)
	sort.Strings(permissions)
	return roleNames, permissions, nil
}
