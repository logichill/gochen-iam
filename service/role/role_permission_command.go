package role

import (
	"context"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
	"slices"
	"strconv"
)

type rolePermissionSources struct {
	Groups bool
	IDs    []int64
}
type rolePermissionAccess struct {
	user   *app.CommandReader[struct{}, *iamentity.User]
	groups *app.CommandReader[struct{}, []*iamentity.Group]
	roles  *app.CommandReader[rolePermissionSources, []*iamentity.Role]
}
type rolePermissionCommand = app.Command[svc.PermissionCheckRequest, *rolePermissionAccess, *svc.PermissionCheckResponse]

func (s *RoleService) compilePermissionCommand() error {
	resources := []app.CommandResource[svc.PermissionCheckRequest]{}
	for _, name := range []string{"user", "groups", "roles"} {
		provider := app.IExecutionDescriptorProvider(s.userRepo.Repo)
		resource := svc.UserResourceKind
		if name == "groups" {
			provider = s.groupRepo.Repo
			resource = "iam.role.effective_groups"
		}
		if name == "roles" {
			provider = s.roleRepo.Repo
			resource = "iam.role.effective_roles"
		}
		descriptor := auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: "check_permission_" + name, Kind: auth.KindRead, Permission: "role:api:read"}}}
		var authorizer *auth.Authorizer
		var err error
		if name == "user" {
			authorizer, err = s.authorizer.Compile(descriptor, provider.ExecutionDescriptor().Metadata())
		} else {
			// 完整有效权限从已授权用户及实际组关系派生。
			authorizer, err = auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: resource, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
		}
		if err != nil {
			return err
		}
		isUser := name == "user"
		resources = append(resources, app.CommandResource[svc.PermissionCheckRequest]{Name: name, Repository: provider, Authorizer: authorizer, Action: "check_permission_" + name, ConditionPath: "authorized user -> trusted group membership -> active direct/group roles; complete effective-permission projection", Intent: func(in svc.PermissionCheckRequest) (auth.Request, error) {
			if isUser {
				if in.UserID <= 0 {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
				}
				return auth.Request{IDs: []string{strconv.FormatInt(in.UserID, 10)}}, nil
			}
			return auth.Request{}, nil
		}})
	}
	command, err := app.NewCommand(app.CommandOptions[svc.PermissionCheckRequest, *rolePermissionAccess, *svc.PermissionCheckResponse]{Resources: resources,
		Access: func(_ context.Context, in svc.PermissionCheckRequest, grants []*app.CommandGrant) (*rolePermissionAccess, error) {
			if len(grants) != 3 || grants[0] == nil || grants[1] == nil || grants[2] == nil {
				return nil, errors.NewCode(errors.InvalidInput, "permission projection requires all grants")
			}
			a := &rolePermissionAccess{}
			var err error
			loadedUser := false
			a.user, err = app.NewCommandReader(s.userRepo.Repo, grants[0], func(ctx context.Context, _ struct{}, condition spec.Spec) (*iamentity.User, error) {
				user, err := s.userRepo.Repo.Get(ctx, in.UserID, condition)
				if err != nil {
					return nil, err
				}
				loadedUser = true
				return user, nil
			})
			if err != nil {
				return nil, err
			}
			knownGroups := map[int64]bool{}
			a.groups, err = app.NewCommandReader(s.groupRepo.Repo, grants[1], func(ctx context.Context, _ struct{}, condition spec.Spec) ([]*iamentity.Group, error) {
				if !loadedUser || !condition.IsAll() {
					return nil, errors.NewCode(errors.Forbidden, "effective groups require complete projection")
				}
				groups, err := s.groupRepo.GroupsForUsers(ctx, []int64{in.UserID}, condition)
				if err != nil {
					return nil, err
				}
				for _, group := range groups.Items {
					knownGroups[group.ID] = true
				}
				return groups.Items, nil
			})
			if err != nil {
				return nil, err
			}
			a.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[2], func(ctx context.Context, sources rolePermissionSources, condition spec.Spec) ([]*iamentity.Role, error) {
				if !loadedUser || !condition.IsAll() {
					return nil, errors.NewCode(errors.Forbidden, "effective roles require complete projection")
				}
				if !sources.Groups {
					if len(sources.IDs) != 1 || sources.IDs[0] != in.UserID {
						return nil, errors.NewCode(errors.Forbidden, "role source differs from trusted user")
					}
					roles, err := s.roleRepo.ActiveRolesForUser(ctx, in.UserID, condition)
					return roles.Items, err
				}
				for _, id := range sources.IDs {
					if !knownGroups[id] {
						return nil, errors.NewCode(errors.Forbidden, "role source differs from trusted groups")
					}
				}
				roles, err := s.roleRepo.RolesForGroups(ctx, sources.IDs, condition)
				return roles.Items, err
			})
			return a, err
		}, Handler: func(ctx context.Context, in svc.PermissionCheckRequest, a *rolePermissionAccess) (*svc.PermissionCheckResponse, error) {
			if _, err := a.user.Read(ctx, struct{}{}); err != nil {
				return nil, err
			}
			direct, err := a.roles.Read(ctx, rolePermissionSources{IDs: []int64{in.UserID}})
			if err != nil {
				return nil, err
			}
			groups, err := a.groups.Read(ctx, struct{}{})
			if err != nil {
				return nil, err
			}
			ids := []int64{}
			for _, group := range groups {
				ids = append(ids, group.ID)
			}
			inherited, err := a.roles.Read(ctx, rolePermissionSources{Groups: true, IDs: ids})
			if err != nil {
				return nil, err
			}
			names, permissions := []string{}, []string{}
			nameSet, permissionSet := map[string]bool{}, map[string]bool{}
			for _, role := range append(direct, inherited...) {
				if !role.IsActive() {
					continue
				}
				if role.Name != "" && !nameSet[role.Name] {
					names = append(names, role.Name)
					nameSet[role.Name] = true
				}
				for _, permission := range role.Permissions {
					if permission != "" && !permissionSet[permission] {
						permissions = append(permissions, permission)
						permissionSet[permission] = true
					}
				}
			}
			slices.Sort(names)
			slices.Sort(permissions)
			return &svc.PermissionCheckResponse{HasPermission: (hostauthz.Principal{Permissions: permissions}).AllowsPermission(in.Permission), Roles: names, Source: "effective"}, nil
		}})
	if err != nil {
		return err
	}
	s.permissionCommand = command
	return nil
}
