package user

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

// UserRoleRemovalInput identifies the user and role whose bindings are removed.
type UserRoleRemovalInput struct {
	UserID, RoleID int64
	Binding        *userrepo.BindingRecord
}

type userRoleRemovalSnapshot struct{ User, Role userGroupTarget }
type userRoleRemovalAccess struct {
	users   *app.CommandRepository[*iamentity.User, int64]
	roles   *app.CommandRepository[*iamentity.Role, int64]
	binding *app.CommandReader[struct{}, struct{}]
	write   *app.CommandWriter[userRoleRemovalSnapshot, struct{}]
	loaded  *userRoleRemovalSnapshot
	scopes  *userBindingScopeAccess
}
type userRoleRemovalCommand = app.Command[UserRoleRemovalInput, *userRoleRemovalAccess, struct{}]

func (s *UserService) compileRoleRemovals() error {
	userFact, err := auth.NewFact("iam.user.role_removal_user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	roleFact, err := auth.NewFact("iam.user.role_removal_role", func(ctx context.Context, req auth.Request) (*iamentity.Role, error) {
		id, err := userGroupFactID(req, svc.RoleResourceKind)
		if err != nil {
			return nil, err
		}
		return s.roleRepo.Repo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.roleRemovals = map[string]*userRoleRemovalCommand{}
	for _, action := range []string{"remove_role", "http_remove_role", "remove_binding", "http_remove_binding"} {
		byBinding := strings.HasSuffix(action, "remove_binding")
		var guards []auth.IPolicy
		if strings.HasPrefix(action, "http_") {
			guards = []auth.IPolicy{userAssociationEntryPolicy{}}
		}
		users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind,
			Actions: []auth.Action{{Name: action + "_user", Kind: auth.KindUpdate, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
			s.userRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userStatusTargetPolicy{userFact})...)
		if err != nil {
			return err
		}
		roles, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind,
			Actions: []auth.Action{{Name: action + "_role", Kind: auth.KindRead, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
			s.roleRepo.Repo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userAssignmentRolePolicy{roleFact})...)
		if err != nil {
			return err
		}
		bindings, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.role_removal.binding",
			Actions: []auth.Action{{Name: action + "_binding", Kind: auth.KindDelete, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
			ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.user.role_removal.binding", System: auth.SystemCheckConstraints,
				UnauthorizedAsDenial: true, Constraints: guards}}}, auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: s.roleBindingSource.ExecutionDescriptor().Metadata()})
		if err != nil {
			return err
		}
		resources := []app.CommandResource[UserRoleRemovalInput]{
			{Name: "user", Repository: s.userRepo, Authorizer: users, Action: action + "_user",
				ConditionPath: "trusted User Fact -> independent user condition -> frozen ownership/version in the binding deletion transaction",
				Intent: func(in UserRoleRemovalInput) (auth.Request, error) {
					if in.UserID <= 0 || in.RoleID <= 0 {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "user and role IDs must be positive")
					}
					if byBinding != (in.Binding != nil) || byBinding && (in.Binding.BindingID <= 0 || in.Binding.UserID != in.UserID || in.Binding.RoleID != in.RoleID) {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "binding removal requires its selected user/role snapshot")
					}
					return auth.Request{IDs: []string{strconv.FormatInt(in.UserID, 10)}}, nil
				}},
			{Name: "role", Repository: s.roleRepo.Repo, Authorizer: roles, Action: action + "_role",
				ConditionPath: "trusted base Role Fact -> platform ownership policy -> independent role condition -> frozen ownership/version in transaction",
				Intent: func(in UserRoleRemovalInput) (auth.Request, error) {
					return auth.Request{IDs: []string{strconv.FormatInt(in.RoleID, 10)}}, nil
				}},
			{Name: "binding", Repository: s.roleBindingSource, Authorizer: bindings, Action: action + "_binding",
				ConditionPath: "complete binding predicate -> CommandWriter -> authorized same-tenant user/role snapshots -> delete all bindings for those real IDs",
				Intent:        func(UserRoleRemovalInput) (auth.Request, error) { return auth.Request{}, nil }},
		}
		if byBinding && s.scopeAuthorizer != nil {
			extra, err := bindingScopeResources[UserRoleRemovalInput](s.scopeAuthorizer, action, "user:api:write", guards)
			if err != nil {
				return err
			}
			resources = append(resources, extra...)
		}
		if byBinding {
			resources[2].ConditionPath = "complete binding predicate -> CommandWriter -> transaction recheck of selected binding/user/role/grant/status -> delete the exact authorized binding snapshot"
		}
		command, err := app.NewCommand(app.CommandOptions[UserRoleRemovalInput, *userRoleRemovalAccess, struct{}]{
			Resources: resources,
			Access: func(ctx context.Context, in UserRoleRemovalInput, grants []*app.CommandGrant) (*userRoleRemovalAccess, error) {
				return s.bindRoleRemoval(ctx, action, in, grants)
			},
			Handler: func(ctx context.Context, _ UserRoleRemovalInput, access *userRoleRemovalAccess) (struct{}, error) {
				if _, err := access.binding.Read(ctx, struct{}{}); err != nil {
					return struct{}{}, err
				}
				user, err := access.users.FromFact(ctx, userFact)
				if err != nil {
					return struct{}{}, err
				}
				role, err := access.roles.FromFact(ctx, roleFact)
				if err != nil {
					return struct{}{}, err
				}
				access.loaded = &userRoleRemovalSnapshot{
					User: userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID},
					Role: userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID},
				}
				return access.write.Write(ctx, *access.loaded)
			},
		})
		if err != nil {
			return err
		}
		s.roleRemovals[action] = command
	}
	return nil
}

func (s *UserService) bindRoleRemoval(ctx context.Context, action string, in UserRoleRemovalInput, grants []*app.CommandGrant) (*userRoleRemovalAccess, error) {
	if strings.HasSuffix(action, "remove_binding") != (in.Binding != nil) {
		return nil, errors.NewCode(errors.InvalidInput, "binding removal capability differs from the selected branch")
	}
	count := 3
	if in.Binding != nil && s.scopeAuthorizer != nil {
		count += 4
	}
	if len(grants) != count || s.roleBindingSource == nil || s.roleBindingSource.repository != s.userRepo {
		return nil, errors.NewCode(errors.InvalidInput, "role removal requires all actual resource grants")
	}
	for i, name := range []string{"user", "role", "binding"} {
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "role removal capability differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		resource, id := "iam.user.role_removal.binding", int64(0)
		if name == "user" {
			resource, id = svc.UserResourceKind, in.UserID
		} else if name == "role" {
			resource, id = svc.RoleResourceKind, in.RoleID
		}
		if req.Resource != resource || req.Action != action+"_"+name || id > 0 && (len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(id, 10)) || id == 0 && len(req.IDs) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "role removal capability differs from its action or target")
		}
	}
	a := &userRoleRemovalAccess{}
	var err error
	a.users, err = app.NewCommandRepository(s.userRepo, grants[0])
	if err != nil {
		return nil, err
	}
	a.roles, err = app.NewCommandRepository(s.roleRepo.Repo, grants[1])
	if err != nil {
		return nil, err
	}
	a.binding, err = app.NewCommandReader(s.roleBindingSource, grants[2], func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
		return struct{}{}, requireRoleAssignmentCatalog(condition)
	})
	if err != nil {
		return nil, err
	}
	if in.Binding != nil && s.scopeAuthorizer != nil {
		a.scopes, err = s.bindBindingScopes(ctx, action, grants[3:], func(binding userrepo.BindingRecord) bool {
			return a.loaded != nil && binding == *in.Binding && binding.UserID == a.loaded.User.ID && binding.RoleID == a.loaded.Role.ID
		})
		if err != nil {
			return nil, err
		}
	}
	userWrite, err := app.NewCommandWriter(s.userRepo, grants[0], func(ctx context.Context, write userRoleRemovalSnapshot, userCondition spec.Spec) (struct{}, error) {
		roleRead, err := app.NewCommandReader(s.roleRepo.Repo, grants[1], func(ctx context.Context, _ struct{}, roleCondition spec.Spec) (struct{}, error) {
			if in.Binding != nil {
				return struct{}{}, s.userRepo.RemoveAuthorizedRoleBinding(ctx, *in.Binding, spec.And(userCondition, write.User.condition()), spec.And(roleCondition, write.Role.condition()))
			}
			return struct{}{}, s.userRepo.RemoveRole(ctx, in.UserID, in.RoleID, spec.And(userCondition, write.User.condition()), spec.And(roleCondition, write.Role.condition()))
		})
		if err != nil {
			return struct{}{}, err
		}
		return roleRead.Read(ctx, struct{}{})
	})
	if err != nil {
		return nil, err
	}
	a.write, err = app.NewCommandWriter(s.roleBindingSource, grants[2], func(ctx context.Context, write userRoleRemovalSnapshot, condition spec.Spec) (struct{}, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return struct{}{}, err
		}
		if a.loaded == nil || write != *a.loaded || write.User.ID != in.UserID || write.Role.ID != in.RoleID || write.User.TenantID != write.Role.TenantID {
			return struct{}{}, errors.NewCode(errors.Forbidden, "binding removal differs from its trusted same-tenant user and role")
		}
		err := s.userRepo.WithinTx(ctx, func(txCtx context.Context) error {
			user, err := a.users.Get(txCtx, in.UserID)
			if err != nil {
				return err
			}
			role, err := a.roles.Get(txCtx, in.RoleID)
			if err != nil {
				return err
			}
			if (userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID}) != write.User ||
				(userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID}) != write.Role {
				return errors.NewCode(errors.Conflict, "user or role changed after removal authorization")
			}
			if in.Binding != nil {
				binding, err := s.readSelectedBinding(txCtx, in, grants[2])
				if err != nil {
					return err
				}
				if a.scopes != nil {
					if err := a.scopes.check(txCtx, *binding); err != nil {
						return err
					}
				}
			}
			_, err = userWrite.Write(txCtx, write)
			return err
		})
		return struct{}{}, err
	})
	return a, err
}

func (s *UserService) readSelectedBinding(ctx context.Context, in UserRoleRemovalInput, grant *app.CommandGrant) (*userrepo.BindingRecord, error) {
	reader, err := app.NewCommandReader(s.roleBindingSource, grant, func(ctx context.Context, _ struct{}, condition spec.Spec) (*userrepo.BindingRecord, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return nil, err
		}
		current, err := s.userRepo.GetRoleBinding(ctx, in.Binding.BindingID)
		if err != nil {
			if errors.Is(err, errors.NotFound) {
				return nil, errors.NewCode(errors.Conflict, "role binding changed after selection")
			}
			return nil, err
		}
		if *current != *in.Binding || current.UserID != in.UserID || current.RoleID != in.RoleID {
			return nil, errors.NewCode(errors.Conflict, "role binding changed after selection")
		}
		return current, nil
	})
	if err != nil {
		return nil, err
	}
	return reader.Read(ctx, struct{}{})
}

func (s *UserService) executeBindingRemoval(ctx context.Context, prefix string, in UserRoleBindingInput) error {
	selector := s.bindingSelectors[prefix+"select_binding"]
	if selector == nil {
		return errors.NewCode(errors.InvalidInput, "binding selection action is not declared")
	}
	binding, err := selector.Execute(ctx, in)
	if err != nil {
		return err
	}
	return s.executeRoleRemoval(ctx, prefix+"remove_binding", UserRoleRemovalInput{UserID: in.UserID, RoleID: binding.RoleID, Binding: binding})
}

func (s *UserService) ExecuteRoleBindingRemovalHTTP(ctx context.Context, in UserRoleBindingInput) error {
	return s.executeBindingRemoval(ctx, "http_", in)
}

func (s *UserService) RoleBindingRemovalAuthorizationBinding() (auth.EntryBinding, error) {
	command := s.roleRemovals["http_remove_binding"]
	selector := s.bindingSelectors["http_select_binding"]
	if command == nil || selector == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "binding removal requires both declared stages")
	}
	binding, err := command.AuthorizationBinding()
	if err != nil {
		return auth.EntryBinding{}, err
	}
	selection, err := selector.AuthorizationBinding()
	if err != nil {
		return auth.EntryBinding{}, err
	}
	binding.Resources = append(binding.Resources, auth.ResourceBinding{Name: "selection_user", Plan: selection.Plan, Action: selection.Action, Source: selection.Source, ConditionPath: selection.ConditionPath})
	for _, resource := range selection.Resources {
		resource.Name = "selection_" + resource.Name
		binding.Resources = append(binding.Resources, resource)
	}
	return binding, nil
}

func (s *UserService) executeRoleRemoval(ctx context.Context, action string, in UserRoleRemovalInput) error {
	command := s.roleRemovals[action]
	if command == nil {
		return errors.NewCode(errors.InvalidInput, "role removal action is not declared")
	}
	_, err := command.Execute(ctx, in)
	return err
}

func (s *UserService) ExecuteRoleRemovalHTTP(ctx context.Context, in UserRoleRemovalInput) error {
	return s.executeRoleRemoval(ctx, "http_remove_role", in)
}

func (s *UserService) RoleRemovalAuthorizationBinding() (auth.EntryBinding, error) {
	command := s.roleRemovals["http_remove_role"]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "role removal HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
