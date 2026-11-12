package user

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// UserGroupWriteInput identifies the requested user/group association.
type UserGroupWriteInput struct{ UserID, GroupID int64 }

type userGroupTarget struct {
	ID, ScopeID       int64
	Version           uint64
	TenantID, OwnerID string
}

func (t userGroupTarget) condition() spec.Spec {
	return spec.And(spec.Eq(meta.ID(), t.ID), spec.Eq(meta.ByField("Version"), t.Version),
		spec.Eq(meta.ByDimension("tenant"), t.TenantID), spec.Eq(meta.ByDimension("scope"), t.ScopeID),
		spec.Eq(meta.ByDimension("owner"), t.OwnerID))
}

type userGroupWrite struct{ User, Group userGroupTarget }
type userGroupWriteAccess struct {
	users  *app.CommandRepository[*iamentity.User, int64]
	groups *app.CommandRepository[*iamentity.Group, int64]
	write  *app.CommandWriter[userGroupWrite, struct{}]
	loaded *userGroupWrite
}
type userGroupWriteCommand = app.Command[UserGroupWriteInput, *userGroupWriteAccess, struct{}]

type userGroupTargetPolicy struct{ target *auth.Fact[*iamentity.Group] }

func (userGroupTargetPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p userGroupTargetPolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.target}
}
func (p userGroupTargetPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	if _, err := p.target.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func userGroupFactID(req auth.Request, resource string) (int64, error) {
	if req.Resource != resource || len(req.IDs) != 1 {
		return 0, errors.NewCode(errors.InvalidInput, "user association requires one target per resource")
	}
	id, err := strconv.ParseInt(req.IDs[0], 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.NewCode(errors.InvalidInput, "association target ID must be positive")
	}
	return id, nil
}

func (s *UserService) compileGroupWrites() error {
	userFact, err := auth.NewFact("iam.user.group_write_user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	groupFact, err := auth.NewFact("iam.user.group_write_group", func(ctx context.Context, req auth.Request) (*iamentity.Group, error) {
		id, err := userGroupFactID(req, svc.GroupResourceKind)
		if err != nil {
			return nil, err
		}
		return s.groupRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.groupWrites = map[string]*userGroupWriteCommand{}
	for _, base := range []string{"assign_group", "remove_group"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			var guards []auth.IPolicy
			if prefix != "" {
				guards = append(guards, userAssociationEntryPolicy{})
			}
			users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind,
				Actions: []auth.Action{{Name: action, Kind: auth.KindUpdate, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
				s.userRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userStatusTargetPolicy{userFact})...)
			if err != nil {
				return err
			}
			groups, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.GroupResourceKind,
				Actions: []auth.Action{{Name: action + "_group", Kind: auth.KindRead, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
				s.groupRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userGroupTargetPolicy{groupFact})...)
			if err != nil {
				return err
			}
			command, err := app.NewCommand(app.CommandOptions[UserGroupWriteInput, *userGroupWriteAccess, struct{}]{
				Resources: []app.CommandResource[UserGroupWriteInput]{
					{Name: "user", Repository: s.userRepo, Authorizer: users, Action: action,
						ConditionPath: "trusted user Fact -> CommandRepository.FromFact -> transaction -> independent user condition and frozen ownership/version",
						Intent: func(in UserGroupWriteInput) (auth.Request, error) {
							if in.UserID <= 0 || in.GroupID <= 0 {
								return auth.Request{}, errors.NewCode(errors.InvalidInput, "user and group IDs must be positive")
							}
							return auth.Request{IDs: []string{strconv.FormatInt(in.UserID, 10)}}, nil
						}},
					{Name: "group", Repository: s.groupRepo, Authorizer: groups, Action: action + "_group",
						ConditionPath: "trusted group Fact -> CommandRepository.FromFact -> transaction -> independent group condition and frozen ownership/version",
						Intent: func(in UserGroupWriteInput) (auth.Request, error) {
							return auth.Request{IDs: []string{strconv.FormatInt(in.GroupID, 10)}}, nil
						}}},
				Access: func(_ context.Context, in UserGroupWriteInput, grants []*app.CommandGrant) (*userGroupWriteAccess, error) {
					return s.bindGroupWrite(action, in, grants)
				},
				Handler: func(ctx context.Context, _ UserGroupWriteInput, access *userGroupWriteAccess) (struct{}, error) {
					user, err := access.users.FromFact(ctx, userFact)
					if err != nil {
						return struct{}{}, err
					}
					group, err := access.groups.FromFact(ctx, groupFact)
					if err != nil {
						return struct{}{}, err
					}
					if user.TenantID != group.TenantID {
						return struct{}{}, errors.NewCode(errors.Forbidden, "user and group must belong to the same tenant")
					}
					access.loaded = &userGroupWrite{
						User:  userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID},
						Group: userGroupTarget{group.ID, group.ManagedScopeID, group.Version, group.TenantID, group.OwnerID},
					}
					return access.write.Write(ctx, *access.loaded)
				}})
			if err != nil {
				return err
			}
			s.groupWrites[action] = command
		}
	}
	return nil
}

func (s *UserService) bindGroupWrite(action string, in UserGroupWriteInput, grants []*app.CommandGrant) (*userGroupWriteAccess, error) {
	if len(grants) != 2 || grants[0] == nil || grants[1] == nil || grants[0].Name() != "user" || grants[1].Name() != "group" {
		return nil, errors.NewCode(errors.InvalidInput, "user group write requires both declared grants")
	}
	for i, expected := range []struct {
		resource, action string
		id               int64
	}{
		{svc.UserResourceKind, action, in.UserID}, {svc.GroupResourceKind, action + "_group", in.GroupID},
	} {
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if req.Resource != expected.resource || req.Action != expected.action || len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(expected.id, 10) {
			return nil, errors.NewCode(errors.InvalidInput, "user group capability differs from its action or target")
		}
	}
	access := &userGroupWriteAccess{}
	var err error
	access.users, err = app.NewCommandRepository(s.userRepo, grants[0])
	if err != nil {
		return nil, err
	}
	access.groups, err = app.NewCommandRepository(s.groupRepo, grants[1])
	if err != nil {
		return nil, err
	}
	access.write, err = app.NewCommandWriter(s.userRepo, grants[0], func(ctx context.Context, write userGroupWrite, condition spec.Spec) (struct{}, error) {
		if access.loaded == nil || write != *access.loaded || write.User.ID != in.UserID || write.Group.ID != in.GroupID || write.User.TenantID != write.Group.TenantID {
			return struct{}{}, errors.NewCode(errors.Forbidden, "association differs from the trusted user and group")
		}
		err := s.userRepo.WithinTx(ctx, func(txCtx context.Context) error {
			user, err := access.users.Get(txCtx, in.UserID)
			if err != nil {
				return err
			}
			if (userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID}) != write.User {
				return errors.NewCode(errors.Conflict, "user ownership or version changed after authorization")
			}
			current, err := access.groups.Get(txCtx, in.GroupID)
			if err != nil {
				return err
			}
			if (userGroupTarget{current.ID, current.ManagedScopeID, current.Version, current.TenantID, current.OwnerID}) != write.Group {
				return errors.NewCode(errors.Conflict, "group ownership or version changed after authorization")
			}
			userCondition := spec.And(condition, write.User.condition())
			// Get applies the group's independent grant before its frozen snapshot is
			// checked again by the association repository in this same transaction.
			if strings.TrimPrefix(action, "http_") == "assign_group" {
				return s.userRepo.AssignToGroup(txCtx, in.UserID, in.GroupID, userCondition, write.Group.condition())
			}
			return s.userRepo.RemoveFromGroup(txCtx, in.UserID, in.GroupID, userCondition, write.Group.condition())
		})
		return struct{}{}, err
	})
	return access, err
}

func (s *UserService) executeGroupWrite(ctx context.Context, action string, in UserGroupWriteInput) error {
	command := s.groupWrites[action]
	if command == nil {
		return errors.NewCode(errors.InvalidInput, "user group write action is not declared")
	}
	_, err := command.Execute(ctx, in)
	return err
}

func (s *UserService) ExecuteGroupWriteHTTP(ctx context.Context, action string, in UserGroupWriteInput) error {
	return s.executeGroupWrite(ctx, "http_"+action, in)
}

func (s *UserService) GroupWriteAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.groupWrites["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user group HTTP write action is not declared")
	}
	return command.AuthorizationBinding()
}
