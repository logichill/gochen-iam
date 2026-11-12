package group

import (
	"context"
	stdErrors "errors"
	"slices"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// GroupAssociationInput contains the requested group and related resource IDs.
type GroupAssociationInput struct {
	ID         int64
	RelatedIDs []int64
}

type associationTarget struct {
	ID                int64
	Version           uint64
	TenantID, OwnerID string
	ScopeID           int64
}

func (t associationTarget) condition() spec.Spec {
	return spec.And(spec.Eq(meta.ID(), t.ID), spec.Eq(meta.ByField("Version"), t.Version),
		spec.Eq(meta.ByDimension("tenant"), t.TenantID), spec.Eq(meta.ByDimension("scope"), t.ScopeID),
		spec.Eq(meta.ByDimension("owner"), t.OwnerID))
}

func groupTarget(g *iamentity.Group) associationTarget {
	return associationTarget{ID: g.GetID(), Version: g.GetVersion(), TenantID: g.TenantID, OwnerID: g.OwnerID, ScopeID: g.ManagedScopeID}
}

type associationWrite struct {
	Group, Related associationTarget
}
type groupAssociationAccess struct {
	groups       *app.CommandRepository[*iamentity.Group, int64]
	users        *app.CommandRepository[*iamentity.User, int64]
	roles        *app.CommandRepository[*iamentity.Role, int64]
	requestedIDs []int64
	write        *app.CommandWriter[associationWrite, struct{}]
}

func (a groupAssociationAccess) readTarget(ctx context.Context, id int64) (associationTarget, error) {
	if id <= 0 || !slices.Contains(a.requestedIDs, id) {
		return associationTarget{}, errors.NewCode(errors.InvalidInput, "related resource ID is outside the requested association")
	}
	if a.roles != nil {
		r, err := a.roles.Get(ctx, id)
		if err != nil {
			return associationTarget{}, err
		}
		return associationTarget{ID: r.GetID(), Version: r.GetVersion(), TenantID: r.TenantID, OwnerID: r.OwnerID, ScopeID: r.NamespaceScopeID}, nil
	}
	u, err := a.users.Get(ctx, id)
	if err != nil {
		return associationTarget{}, err
	}
	return associationTarget{ID: u.GetID(), Version: u.GetVersion(), TenantID: u.TenantID, OwnerID: u.OwnerID, ScopeID: u.ManagedScopeID}, nil
}

type groupAssociationCommand = app.Command[GroupAssociationInput, groupAssociationAccess, *svc.BulkOperationResponse]

type groupAssociationEntryPolicy struct{}

func (groupAssociationEntryPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (groupAssociationEntryPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	id, _ := strconv.ParseInt(principal.SubjectID, 10, 64)
	if id <= 0 {
		return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	kind := iamauth.ActiveScopeKindFromContext(ctx)
	if !tenant.CurrentContext(ctx).IsSingle() && kind != string(iamperm.ScopePlatform) && kind != string(iamperm.ScopeTenant) {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "当前授权域不允许访问此权限")
	}
	if !principal.AllowsPermission(svc.GroupPermissionSet.Code(iamperm.ActionManage)) {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "权限不足")
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *GroupService) compileAssociationCommands() error {
	if s.groupRepo == nil || s.groupRepo.Repo == nil || s.userRepo == nil || s.userRepo.Repo == nil || s.roleRepo == nil || s.roleRepo.Repo == nil || s.authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "group service requires the actual group, user and role repositories and IAM declarations")
	}
	s.associationCommands = map[string]*groupAssociationCommand{}
	for _, base := range []string{"add_user", "remove_user", "bulk_add_users", "add_role", "remove_role"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			command, err := s.compileAssociationCommand(action)
			if err != nil {
				return err
			}
			s.associationCommands[action] = command
		}
	}
	return nil
}

func (s *GroupService) compileAssociationCommand(action string) (*groupAssociationCommand, error) {
	base := strings.TrimPrefix(action, "http_")
	role := base == "add_role" || base == "remove_role"
	var policies []auth.IPolicy
	if strings.HasPrefix(action, "http_") {
		policies = []auth.IPolicy{groupAssociationEntryPolicy{}}
	}
	compile := func(provider app.IExecutionDescriptorProvider, resource, name string, kind auth.Kind) (*auth.Authorizer, error) {
		return s.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: name, Kind: kind, Permission: svc.GroupPermissionSet.Code(iamperm.ActionWrite)}}}, provider.ExecutionDescriptor().Metadata(), policies...)
	}
	primary, err := compile(s.groupRepo, svc.GroupResourceKind, action, auth.KindUpdate)
	if err != nil {
		return nil, err
	}
	var targetProvider app.IExecutionDescriptorProvider = s.userRepo.Repo
	targetKind := svc.UserResourceKind
	if role {
		targetProvider, targetKind = s.roleRepo.Repo, svc.RoleResourceKind
	}
	target, err := compile(targetProvider, targetKind, action+"_target", auth.KindRead)
	if err != nil {
		return nil, err
	}
	resources := []app.CommandResource[GroupAssociationInput]{
		{Name: "group", Repository: s.groupRepo, Authorizer: primary, Action: action,
			ConditionPath: "CommandWriter -> transaction -> group condition and frozen ownership/version -> association mutation",
			Intent: func(in GroupAssociationInput) (auth.Request, error) {
				if in.ID <= 0 {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "group ID must be positive")
				}
				if base != "bulk_add_users" && (len(in.RelatedIDs) != 1 || in.RelatedIDs[0] <= 0) {
					return auth.Request{}, errors.NewCode(errors.InvalidInput, "one positive related resource ID is required")
				}
				return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
			}},
		{Name: "target", Repository: targetProvider, Authorizer: target, Action: action + "_target",
			ConditionPath: "CommandRepository.Get -> exact requested ID and target spec -> actual base user/role repository -> transaction recheck and frozen ownership/version",
			Intent: func(in GroupAssociationInput) (auth.Request, error) {
				ids := make([]string, 0, len(in.RelatedIDs))
				for _, id := range in.RelatedIDs {
					if id > 0 {
						ids = append(ids, strconv.FormatInt(id, 10))
					}
				}
				return auth.Request{IDs: ids}, nil
			}},
	}
	return app.NewCommand(app.CommandOptions[GroupAssociationInput, groupAssociationAccess, *svc.BulkOperationResponse]{Resources: resources,
		Access: func(_ context.Context, in GroupAssociationInput, grants []*app.CommandGrant) (groupAssociationAccess, error) {
			return s.bindAssociationAccess(action, in, grants)
		}, Handler: func(ctx context.Context, in GroupAssociationInput, access groupAssociationAccess) (*svc.BulkOperationResponse, error) {
			response := &svc.BulkOperationResponse{}
			err := s.groupRepo.WithinTx(ctx, func(txCtx context.Context) error {
				if len(in.RelatedIDs) == 0 {
					return nil
				}
				group, err := access.groups.Get(txCtx, in.ID)
				if err != nil {
					if base != "bulk_add_users" {
						return err
					}
					for range in.RelatedIDs {
						response.FailureCount++
						response.Errors = append(response.Errors, err)
					}
					return errBulkAddUsersRollback
				}
				writes := make([]associationWrite, 0, len(in.RelatedIDs))
				// All related resources are checked before the first association write.
				for _, id := range in.RelatedIDs {
					related, err := access.readTarget(txCtx, id)
					if err == nil && related.TenantID != group.TenantID {
						err = errors.NewCode(errors.Forbidden, "group and related resource must belong to the same tenant")
					}
					if err != nil {
						if base != "bulk_add_users" {
							return err
						}
						response.FailureCount++
						response.Errors = append(response.Errors, err)
						continue
					}
					writes = append(writes, associationWrite{Group: groupTarget(group), Related: related})
				}
				if response.FailureCount > 0 {
					return errBulkAddUsersRollback
				}
				for _, write := range writes {
					if _, err := access.write.Write(txCtx, write); err != nil {
						if base != "bulk_add_users" {
							return err
						}
						response.FailureCount++
						response.Errors = append(response.Errors, err)
					} else {
						response.SuccessCount++
					}
				}
				if response.FailureCount > 0 {
					response.SuccessCount = 0
					return errBulkAddUsersRollback
				}
				return nil
			})
			if stdErrors.Is(err, errBulkAddUsersRollback) {
				return response, nil
			}
			return response, err
		}})
}

func (s *GroupService) bindAssociationAccess(action string, in GroupAssociationInput, grants []*app.CommandGrant) (groupAssociationAccess, error) {
	var access groupAssociationAccess
	if len(grants) != 2 || grants[0] == nil || grants[1] == nil || grants[0].Name() != "group" || grants[1].Name() != "target" {
		return access, errors.NewCode(errors.InvalidInput, "group association requires both declared resource grants")
	}
	base := strings.TrimPrefix(action, "http_")
	role := base == "add_role" || base == "remove_role"
	targetKind := svc.UserResourceKind
	if role {
		targetKind = svc.RoleResourceKind
	}
	for i, resource := range []string{svc.GroupResourceKind, targetKind} {
		req, err := grants[i].Request()
		if err != nil {
			return access, err
		}
		expected := action
		if i == 1 {
			expected += "_target"
		}
		if req.Resource != resource || req.Action != expected {
			return access, errors.NewCode(errors.InvalidInput, "group association capability differs from its declaration")
		}
	}
	var err error
	access.groups, err = app.NewCommandRepository(s.groupRepo, grants[0])
	if err != nil {
		return access, err
	}
	access.requestedIDs = append([]int64(nil), in.RelatedIDs...)
	if role {
		access.roles, err = app.NewCommandRepository(s.roleRepo.Repo, grants[1])
	} else {
		access.users, err = app.NewCommandRepository(s.userRepo.Repo, grants[1])
	}
	if err != nil {
		return access, err
	}
	access.write, err = app.NewCommandWriter(s.groupRepo, grants[0], func(ctx context.Context, write associationWrite, condition spec.Spec) (struct{}, error) {
		if write.Group.ID != in.ID || write.Group.TenantID != write.Related.TenantID {
			return struct{}{}, errors.NewCode(errors.Forbidden, "association differs from the declared group or tenant")
		}
		err := s.groupRepo.WithinTx(ctx, func(txCtx context.Context) error {
			current, err := access.readTarget(txCtx, write.Related.ID)
			if err != nil {
				return err
			}
			if current != write.Related {
				return errors.NewCode(errors.Conflict, "related resource ownership or version changed")
			}
			groupCondition := spec.And(condition, write.Group.condition())
			relatedCondition := current.condition()
			switch base {
			case "add_user", "bulk_add_users":
				return s.groupRepo.AddUserToGroup(txCtx, in.ID, current.ID, groupCondition, relatedCondition)
			case "remove_user":
				return s.groupRepo.RemoveUserFromGroup(txCtx, in.ID, current.ID, groupCondition, relatedCondition)
			case "add_role":
				return s.groupRepo.AddDefaultRole(txCtx, in.ID, current.ID, groupCondition, relatedCondition)
			case "remove_role":
				return s.groupRepo.RemoveDefaultRole(txCtx, in.ID, current.ID, groupCondition, relatedCondition)
			}
			return errors.NewCode(errors.InvalidInput, "group association action is not declared")
		})
		return struct{}{}, err
	})
	return access, err
}

func (s *GroupService) executeAssociation(ctx context.Context, action string, in GroupAssociationInput) (*svc.BulkOperationResponse, error) {
	command := s.associationCommands[action]
	if command == nil {
		return nil, errors.NewCode(errors.InvalidInput, "group association action is not declared")
	}
	result, err := command.Execute(ctx, in)
	// Batch permission failures retain the existing per-item response contract.
	if strings.TrimPrefix(action, "http_") == "bulk_add_users" && (errors.Is(err, errors.Forbidden) || errors.Is(err, errors.Unauthorized)) {
		result = &svc.BulkOperationResponse{}
		for range in.RelatedIDs {
			result.FailureCount++
			result.Errors = append(result.Errors, err)
		}
		return result, nil
	}
	return result, err
}

func (s *GroupService) ExecuteAssociationHTTP(ctx context.Context, action string, in GroupAssociationInput) (*svc.BulkOperationResponse, error) {
	return s.executeAssociation(ctx, "http_"+action, in)
}

func (s *GroupService) AssociationAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.associationCommands["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "group association HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
