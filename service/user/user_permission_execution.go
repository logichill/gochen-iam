package user

import (
	"context"
	"sort"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/auth"
	"gochen/errors"
)

func (s *UserService) compilePermissionExecutions() error {
	s.permissionExecutions = map[string]*auth.Authorizer{}
	user, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind,
		Actions: []auth.Action{{Name: "permissions", Kind: auth.KindRead, Permission: "user:api:read"}}}, s.userRepo.ExecutionDescriptor().Metadata())
	if err != nil {
		return err
	}
	s.permissionExecutions["user"] = user
	// Related rows are trusted credential facts of the already authorized user.
	// Their readers select only real user-role/group links and do not preload
	// unrelated resources; they retain the previous effective-permissions semantics.
	for _, name := range []string{"roles", "groups"} {
		metadata := s.roleRepo.ExecutionDescriptor().Metadata()
		if name == "groups" {
			metadata = s.groupRepo.ExecutionDescriptor().Metadata()
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.permission." + name,
			Actions: []auth.Action{{Name: "permission_" + name, Kind: auth.KindList, Permission: "user:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "iam.user.permission_projection." + name, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: metadata})
		if err != nil {
			return err
		}
		s.permissionExecutions[name] = authorizer
	}
	return nil
}

func (s *UserService) PermissionAuthorizationBinding() (auth.EntryBinding, error) {
	binding, err := svc.DeclaredExecutionBinding(s.permissionExecutions["user"], "IAM UserService.UserPermissions/CheckPermission", "compiled user permission action -> conditional same-tenant user read and active-status check")
	if err != nil {
		return auth.EntryBinding{}, err
	}
	for _, name := range []string{"roles", "groups"} {
		extra, err := svc.DeclaredExecutionBinding(s.permissionExecutions[name], "IAM UserService permission "+name, "compiled permission projection -> authorized user ID -> real user/group role links -> independent conditional relation queries; no association preloads")
		if err != nil {
			return auth.EntryBinding{}, err
		}
		binding.Resources = append(binding.Resources, auth.ResourceBinding{Name: name, Plan: extra.Plan, Action: extra.Action, Source: extra.Source, ConditionPath: extra.ConditionPath})
	}
	return binding, nil
}

func (s *UserService) readUserPermissions(ctx context.Context, userID int64) ([]string, error) {
	if userID <= 0 {
		return nil, errors.NewCode(errors.InvalidInput, "user ID must be positive")
	}
	userCondition, err := svc.DeclaredCondition(ctx, s.permissionExecutions["user"], strconv.FormatInt(userID, 10))
	if err != nil {
		return nil, err
	}
	roleCondition, err := svc.DeclaredCondition(ctx, s.permissionExecutions["roles"])
	if err != nil {
		return nil, err
	}
	groupCondition, err := svc.DeclaredCondition(ctx, s.permissionExecutions["groups"])
	if err != nil {
		return nil, err
	}
	user, err := s.userRepo.Repo.Get(ctx, userID, userCondition)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errors.NewCode(errors.Forbidden, "用户账户已被禁用")
	}
	direct, err := s.roleRepo.ActiveRolesForUser(ctx, userID, roleCondition)
	if err != nil {
		return nil, err
	}
	groups, err := s.groupRepo.GroupsForUsers(ctx, []int64{userID}, groupCondition)
	if err != nil {
		return nil, err
	}
	groupIDs := make([]int64, 0, len(groups.Items))
	for _, group := range groups.Items {
		groupIDs = append(groupIDs, group.ID)
	}
	inherited, err := s.roleRepo.RolesForGroups(ctx, groupIDs, roleCondition)
	if err != nil {
		return nil, err
	}
	permissions := map[string]bool{}
	for _, roles := range [][]*iamentity.Role{direct.Items, inherited.Items} {
		for _, role := range roles {
			if role != nil && role.IsActive() {
				for _, permission := range role.Permissions {
					if p := strings.TrimSpace(permission); p != "" {
						permissions[p] = true
					}
				}
			}
		}
	}
	result := make([]string, 0, len(permissions))
	for permission := range permissions {
		result = append(result, permission)
	}
	sort.Strings(result)
	return result, nil
}
