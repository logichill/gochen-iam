package user

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type userBindingRoleProjection struct {
	Role    *iamentity.Role
	Visible bool
}
type userRoleBindingReadAccess struct {
	user         *app.CommandRepository[*iamentity.User, int64]
	bindings     *app.CommandReader[int64, []userrepo.BindingRecord]
	roles        *app.CommandReader[userrepo.BindingRecord, userBindingRoleProjection]
	scopes       *userBindingScopeAccess
	displayScope *app.CommandReader[int64, *iamentity.Scope]
	ancestor     *app.CommandReader[userrepo.BindingRecord, bool]
	knownScopes  map[int64]bool
}
type userRoleBindingReadCommand = app.Command[int64, *userRoleBindingReadAccess, []*svc.UserRoleBindingDetail]

func (s *UserService) compileRoleBindingReads() error {
	target, err := auth.NewFact("iam.user.role_binding_read_user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.bindingReads = map[string]*userRoleBindingReadCommand{}
	for _, action := range []string{"role_bindings", "http_role_bindings"} {
		var guards []auth.IPolicy
		if strings.HasPrefix(action, "http_") {
			guards = []auth.IPolicy{userAssociationEntryPolicy{}}
		}
		users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind, Actions: []auth.Action{{Name: action + "_user", Kind: auth.KindRead, Permission: "user:api:read"}}},
			s.userRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userStatusTargetPolicy{target})...)
		if err != nil {
			return err
		}
		resources := []app.CommandResource[int64]{{Name: "user", Repository: s.userRepo, Authorizer: users, Action: action + "_user",
			ConditionPath: "trusted User Fact -> independent user condition -> this user's active direct bindings",
			Intent: func(id int64) (auth.Request, error) {
				if id <= 0 {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
				}
				return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
			}}}
		for _, name := range []string{"binding", "role"} {
			provider := app.IExecutionDescriptorProvider(s.roleBindingSource)
			if name == "role" {
				provider = s.roleRepo.Repo
			}
			authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.binding_projection." + name,
				Actions: []auth.Action{{Name: action + "_" + name, Kind: auth.KindRead, Permission: "user:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
				Rules: []auth.Rule{{ID: "iam.user.binding_projection." + name, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}},
				auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
			if err != nil {
				return err
			}
			resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
				ConditionPath: "complete projection predicate -> authorized user -> real binding/role relation within its tenant -> existing deleted/invisible disclosure",
				Intent:        func(int64) (auth.Request, error) { return auth.Request{}, nil }})
		}
		if s.scopeAuthorizer != nil {
			extra, err := bindingScopeResources[int64](s.scopeAuthorizer, action, "user:api:read", guards)
			if err != nil {
				return err
			}
			resources = append(resources, extra...)
		}
		command, err := app.NewCommand(app.CommandOptions[int64, *userRoleBindingReadAccess, []*svc.UserRoleBindingDetail]{Resources: resources,
			Access: func(ctx context.Context, id int64, grants []*app.CommandGrant) (*userRoleBindingReadAccess, error) {
				return s.bindRoleBindingRead(ctx, action, id, target, grants)
			},
			Handler: executeRoleBindingRead,
		})
		if err != nil {
			return err
		}
		s.bindingReads[action] = command
	}
	return nil
}

func (s *UserService) bindRoleBindingRead(ctx context.Context, action string, id int64, target *auth.Fact[*iamentity.User], grants []*app.CommandGrant) (*userRoleBindingReadAccess, error) {
	count := 3
	if s.scopeAuthorizer != nil {
		count += 4
	}
	if len(grants) != count || s.roleBindingSource == nil || s.roleBindingSource.repository != s.userRepo {
		return nil, errors.NewCode(errors.InvalidInput, "binding projection requires all actual resource grants")
	}
	for i, name := range []string{"user", "binding", "role"} {
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "binding projection capability differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		resource := "iam.user.binding_projection." + name
		if i == 0 {
			resource = svc.UserResourceKind
		}
		if req.Resource != resource || req.Action != action+"_"+name || i == 0 && (len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(id, 10)) || i > 0 && len(req.IDs) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "binding projection differs from its action or user")
		}
	}
	a := &userRoleBindingReadAccess{knownScopes: map[int64]bool{}}
	var err error
	a.user, err = app.NewCommandRepository(s.userRepo, grants[0])
	if err != nil {
		return nil, err
	}
	user, err := a.user.FromFact(ctx, target)
	if err != nil {
		return nil, err
	}
	known := map[int64]userrepo.BindingRecord{}
	knownRoles := map[int64]*iamentity.Role{}
	knownBinding := func(binding userrepo.BindingRecord) bool {
		current, ok := known[binding.BindingID]
		return ok && current == binding
	}
	a.bindings, err = app.NewCommandReader(s.roleBindingSource, grants[1], func(ctx context.Context, userID int64, condition spec.Spec) ([]userrepo.BindingRecord, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return nil, err
		}
		if userID != id || user.ID != id {
			return nil, errors.NewCode(errors.Forbidden, "binding projection differs from its trusted user")
		}
		bindings, err := s.userRepo.ListRoleBindings(ctx, userID)
		if err != nil {
			return nil, err
		}
		result := make([]userrepo.BindingRecord, 0, len(bindings))
		for _, binding := range bindings {
			current := userrepo.BindingRecord{BindingID: binding.BindingID, UserID: id, RoleID: binding.RoleID, GrantScopeID: binding.GrantScopeID, Status: binding.Status}
			known[current.BindingID] = current
			result = append(result, current)
		}
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	if s.scopeAuthorizer != nil {
		a.scopes, err = s.bindBindingScopes(ctx, action, grants[3:], knownBinding)
		if err != nil {
			return nil, err
		}
		_, provider, err := s.scopeAuthorizer.TenantScopeProviders()
		if err != nil {
			return nil, err
		}
		a.displayScope, err = app.NewCommandReader(provider, grants[3], func(ctx context.Context, scopeID int64, condition spec.Spec) (*iamentity.Scope, error) {
			if err := requireRoleAssignmentCatalog(condition); err != nil {
				return nil, err
			}
			if !a.knownScopes[scopeID] {
				return nil, errors.NewCode(errors.Forbidden, "scope display differs from a trusted visible binding or role")
			}
			return s.scopeAuthorizer.Scope(ctx, scopeID)
		})
		if err != nil {
			return nil, err
		}
		a.ancestor, err = app.NewCommandReader(provider, grants[4], func(ctx context.Context, binding userrepo.BindingRecord, condition spec.Spec) (bool, error) {
			if err := requireRoleAssignmentCatalog(condition); err != nil {
				return false, err
			}
			role := knownRoles[binding.BindingID]
			if !knownBinding(binding) || role == nil || role.ID != binding.RoleID || a.scopes.root == nil {
				return false, errors.NewCode(errors.Forbidden, "ancestor projection requires a trusted single tenant binding and role")
			}
			root, err := a.scopes.root.Read(ctx)
			if err != nil {
				return false, err
			}
			return s.scopeAuthorizer.ScopeCovers(ctx, role.NamespaceScopeID, root.ID)
		})
		if err != nil {
			return nil, err
		}
	}
	a.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[2], func(ctx context.Context, binding userrepo.BindingRecord, condition spec.Spec) (userBindingRoleProjection, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return userBindingRoleProjection{}, err
		}
		if !knownBinding(binding) {
			return userBindingRoleProjection{}, errors.NewCode(errors.Forbidden, "role projection differs from a trusted user binding")
		}
		role, err := s.roleRepo.Repo.Get(ctx, binding.RoleID, condition)
		visible := err == nil
		if errors.Is(err, errors.NotFound) {
			global, bindErr := svc.BindTenantGlobalScopeContext(ctx, user.TenantID)
			if bindErr != nil {
				return userBindingRoleProjection{}, bindErr
			}
			role, err = s.roleRepo.Repo.Get(global, binding.RoleID, condition)
		}
		if errors.Is(err, errors.NotFound) {
			return userBindingRoleProjection{}, nil
		}
		if err != nil {
			return userBindingRoleProjection{}, err
		}
		if role.ID != binding.RoleID || role.TenantID != user.TenantID {
			return userBindingRoleProjection{}, errors.NewCode(errors.Forbidden, "role projection differs from its same-tenant binding")
		}
		knownRoles[binding.BindingID] = role
		if !visible && tenant.CurrentContext(ctx).IsSingle() && a.ancestor != nil {
			visible, err = a.ancestor.Read(ctx, binding)
			if err != nil {
				return userBindingRoleProjection{}, err
			}
		}
		if visible && role.NamespaceScopeID > 0 {
			a.knownScopes[role.NamespaceScopeID] = true
		}
		return userBindingRoleProjection{Role: role, Visible: visible}, nil
	})
	return a, err
}

func executeRoleBindingRead(ctx context.Context, id int64, a *userRoleBindingReadAccess) ([]*svc.UserRoleBindingDetail, error) {
	if a.scopes != nil {
		if err := a.scopes.preflight(ctx); err != nil {
			return nil, err
		}
	}
	bindings, err := a.bindings.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	result := make([]*svc.UserRoleBindingDetail, 0, len(bindings))
	for _, binding := range bindings {
		if a.scopes != nil {
			if err := a.scopes.check(ctx, binding); err != nil {
				if errors.Is(err, errors.Forbidden) {
					continue
				}
				return nil, err
			}
		}
		projection, err := a.roles.Read(ctx, binding)
		if err != nil {
			return nil, err
		}
		detail := &svc.UserRoleBindingDetail{BindingID: binding.BindingID, UserID: id, RoleID: binding.RoleID, GrantScopeID: binding.GrantScopeID, Status: binding.Status, Permissions: []string{}}
		if projection.Role == nil {
			detail.RoleName = fmt.Sprintf("已删除角色 #%d", binding.RoleID)
		} else if !projection.Visible {
			detail.RoleName = fmt.Sprintf("不可见角色 #%d", binding.RoleID)
		} else {
			detail.RoleName, detail.RoleCode = projection.Role.Name, projection.Role.Code
			detail.NamespaceScopeID = projection.Role.NamespaceScopeID
			detail.Permissions = append([]string(nil), projection.Role.Permissions...)
		}
		if a.displayScope != nil {
			a.knownScopes[binding.GrantScopeID] = true
			if scope, err := a.displayScope.Read(ctx, binding.GrantScopeID); err == nil && scope != nil {
				detail.GrantScopeKey, detail.GrantScopeKind = scope.Key, scope.Type
			}
			if projection.Visible && detail.NamespaceScopeID > 0 {
				if scope, err := a.displayScope.Read(ctx, detail.NamespaceScopeID); err == nil && scope != nil {
					detail.NamespaceScopeKey, detail.NamespaceScopeKind = scope.Key, scope.Type
				}
			}
		}
		result = append(result, detail)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].GrantScopeID != result[j].GrantScopeID {
			return result[i].GrantScopeID < result[j].GrantScopeID
		}
		if result[i].RoleName != result[j].RoleName {
			return result[i].RoleName < result[j].RoleName
		}
		return result[i].BindingID < result[j].BindingID
	})
	return result, nil
}

func (s *UserService) ExecuteRoleBindingReadHTTP(ctx context.Context, id int64) ([]*svc.UserRoleBindingDetail, error) {
	command := s.bindingReads["http_role_bindings"]
	if command == nil {
		return nil, errors.NewCode(errors.InvalidInput, "binding projection HTTP action is not declared")
	}
	return command.Execute(ctx, id)
}

func (s *UserService) RoleBindingReadAuthorizationBinding() (auth.EntryBinding, error) {
	command := s.bindingReads["http_role_bindings"]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "binding projection HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
