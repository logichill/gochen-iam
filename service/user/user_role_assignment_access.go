package user

import (
	"context"
	"strconv"

	svc "gochen-iam/service"
	"gochen-iam/tenant"
	"gochen/app"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func (s *UserService) bindRoleAssignment(ctx context.Context, action string, in UserRoleAssignmentInput, grants []*app.CommandGrant) (*userRoleAssignmentAccess, error) {
	names := []string{"user", "role", "binding"}
	if s.scopeAuthorizer != nil {
		names = append(names, "scope", "visibility", "tenant", "root")
	}
	if len(grants) != len(names) || s.roleBindingSource == nil || s.roleBindingSource.repository != s.userRepo {
		return nil, errors.NewCode(errors.InvalidInput, "role assignment requires all actual declared resource grants")
	}
	for i, name := range names {
		grant := grants[i]
		if (name == "tenant" || name == "root") && !tenant.CurrentContext(ctx).IsSingle() {
			if grant != nil {
				return nil, errors.NewCode(errors.InvalidInput, "tenant root capability is outside the selected assignment branch")
			}
			continue
		}
		if grant == nil || grant.Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "role assignment capability differs from its declaration")
		}
		req, err := grant.Request()
		if err != nil {
			return nil, err
		}
		resource := "iam.user.role_assignment." + name
		if name == "user" {
			resource = svc.UserResourceKind
		} else if name == "role" {
			resource = svc.RoleResourceKind
		}
		if req.Resource != resource || req.Action != action+"_"+name {
			return nil, errors.NewCode(errors.InvalidInput, "role assignment capability differs from its resource or action")
		}
		if name == "user" || name == "role" {
			id := in.UserID
			if name == "role" {
				id = in.RoleID
			}
			if len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(id, 10) {
				return nil, errors.NewCode(errors.InvalidInput, "role assignment target differs from its intent")
			}
		}
	}
	a := &userRoleAssignmentAccess{}
	var err error
	a.users, err = app.NewCommandRepository(s.userRepo, grants[0])
	if err != nil {
		return nil, err
	}
	a.roles, err = app.NewCommandRepository(s.roleRepo.Repo, grants[1])
	if err != nil {
		return nil, err
	}
	a.bindingGuard, err = app.NewCommandReader(s.roleBindingSource, grants[2], func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
		return struct{}{}, requireRoleAssignmentCatalog(condition)
	})
	if err != nil {
		return nil, err
	}
	if s.scopeAuthorizer != nil {
		_, provider, err := s.scopeAuthorizer.TenantScopeProviders()
		if err != nil {
			return nil, err
		}
		a.scopeGuard, err = app.NewCommandReader(provider, grants[3], func(_ context.Context, _ struct{}, condition spec.Spec) (struct{}, error) {
			return struct{}{}, requireRoleAssignmentCatalog(condition)
		})
		if err != nil {
			return nil, err
		}
		a.visibility, err = app.NewCommandReader(provider, grants[4], func(ctx context.Context, scopeID int64, condition spec.Spec) (struct{}, error) {
			if err := requireRoleAssignmentCatalog(condition); err != nil {
				return struct{}{}, err
			}
			if a.loaded == nil || a.trustedRole == nil || scopeID != a.loaded.ScopeID || a.trustedRole.ID != in.RoleID ||
				(userGroupTarget{a.trustedRole.ID, a.trustedRole.NamespaceScopeID, a.trustedRole.Version, a.trustedRole.TenantID, a.trustedRole.OwnerID}) != a.loaded.Role || a.trustedRole.Status != a.loaded.RoleStatus {
				return struct{}{}, errors.NewCode(errors.Forbidden, "grant scope differs from the trusted assignment")
			}
			return struct{}{}, s.ensureGrantScopeAllowed(ctx, a.trustedRole, scopeID)
		})
		if err != nil {
			return nil, err
		}
		if tenant.CurrentContext(ctx).IsSingle() {
			a.root, err = s.scopeAuthorizer.BindTenantScopeReader(grants[5], grants[6])
			if err != nil {
				return nil, err
			}
		}
	}
	userWrite, err := app.NewCommandWriter(s.userRepo, grants[0], func(ctx context.Context, write userRoleAssignmentSnapshot, userCondition spec.Spec) (struct{}, error) {
		roles, err := app.NewCommandReader(s.roleRepo.Repo, grants[1], func(ctx context.Context, _ struct{}, roleCondition spec.Spec) (struct{}, error) {
			roleCondition = spec.And(roleCondition, write.Role.condition(), spec.Eq(meta.ByField("Status"), write.RoleStatus))
			return struct{}{}, s.roleBindingSource.repository.AssignRole(ctx, in.UserID, in.RoleID, write.ScopeID, spec.And(userCondition, write.User.condition()), roleCondition)
		})
		if err != nil {
			return struct{}{}, err
		}
		return roles.Read(ctx, struct{}{})
	})
	if err != nil {
		return nil, err
	}
	a.write, err = app.NewCommandWriter(s.roleBindingSource, grants[2], func(ctx context.Context, write userRoleAssignmentSnapshot, condition spec.Spec) (struct{}, error) {
		if err := requireRoleAssignmentCatalog(condition); err != nil {
			return struct{}{}, err
		}
		if a.loaded == nil || write != *a.loaded || write.User.ID != in.UserID || write.Role.ID != in.RoleID || write.User.TenantID != write.Role.TenantID || write.RoleStatus != svc.RoleStatusActive {
			return struct{}{}, errors.NewCode(errors.Forbidden, "role binding differs from its trusted assignment")
		}
		if in.GrantScopeID != nil && *in.GrantScopeID > 0 && write.ScopeID != *in.GrantScopeID {
			return struct{}{}, errors.NewCode(errors.Forbidden, "role binding differs from the requested grant scope")
		}
		if !tenant.CurrentContext(ctx).IsSingle() && (in.GrantScopeID == nil || *in.GrantScopeID <= 0) {
			expected := write.Role.ScopeID
			if activeID := svc.ManagedScopeIDFromContext(ctx); activeID > 0 {
				expected = activeID
			}
			if write.ScopeID != expected {
				return struct{}{}, errors.NewCode(errors.Forbidden, "role binding differs from the default grant scope")
			}
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
			current := userRoleAssignmentSnapshot{
				User:    userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID},
				Role:    userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID},
				ScopeID: write.ScopeID, RoleStatus: role.Status,
			}
			if current != write {
				return errors.NewCode(errors.Conflict, "user or role changed after assignment authorization")
			}
			if a.root != nil {
				root, err := a.root.Read(txCtx)
				if err != nil {
					return err
				}
				if root.ID != write.ScopeID {
					return errors.NewCode(errors.Conflict, "tenant root changed after assignment authorization")
				}
			}
			if err := a.checkScope(txCtx); err != nil {
				return err
			}
			_, err = userWrite.Write(txCtx, write)
			return err
		})
		return struct{}{}, err
	})
	return a, err
}

func requireRoleAssignmentCatalog(condition spec.Spec) error {
	if !condition.IsAll() {
		return errors.NewCode(errors.Forbidden, "user role bindings require the complete authorized binding and scope predicate")
	}
	return nil
}
