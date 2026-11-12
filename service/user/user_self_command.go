package user

import (
	"context"
	"strconv"
	"time"

	iamentity "gochen-iam/entity"
	"gochen-iam/repo/relations"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type userSelfInput struct {
	ID       int64
	Profile  svc.UpdateUserRequest
	Password svc.ChangePasswordRequest
}
type userSelfAccess struct {
	users  *app.CommandRepository[*iamentity.User, int64]
	groups *app.CommandReader[int64, relations.Catalog[*iamentity.Group]]
	roles  *app.CommandReader[int64, relations.Catalog[*iamentity.Role]]
	email  *app.CommandReader[string, bool]
}
type userSelfCommand = app.Command[userSelfInput, *userSelfAccess, *iamentity.User]

// Self action labels describe authenticated identity checks. Writes retain
// their existing explicit DataScope, including System.
type userSelfPolicy struct {
	target *auth.Fact[*iamentity.User]
	write  bool
}

func (userSelfPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (p userSelfPolicy) FactSources() []auth.IFactSource {
	if p.target == nil {
		return nil
	}
	return []auth.IFactSource{p.target}
}
func (p userSelfPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	_, err = svc.TenantIDFromContext(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	condition := spec.All()
	if p.target != nil {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return auth.Decision{}, err
		}
		if !principal.IsSystem {
			subject, err := strconv.ParseInt(principal.SubjectID, 10, 64)
			if err != nil || subject <= 0 {
				return auth.Decision{}, errors.NewCode(errors.Unauthorized, "用户未认证")
			}
			if subject != id {
				return auth.Decision{}, errors.NewCode(errors.Forbidden, "只能操作本人资料")
			}
		}
		if _, err := p.target.Get(ctx, req); err != nil {
			return auth.Decision{}, err
		}
		if p.write {
			condition = spec.And(condition, svc.DataScopeSpec(ctx))
		}
	}
	return auth.Decision{Allowed: true, Spec: condition}, nil
}

func (s *UserService) compileSelfCommands() error {
	target, err := auth.NewFact("iam.user.self_target", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		user, err := s.userRepo.Get(ctx, id, spec.All())
		if err != nil {
			return nil, err
		}
		if _, err := svc.PreflightTenant(ctx, s.scopeAuthorizer, user.TenantID, ""); err != nil {
			return nil, err
		}
		tenantID, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return nil, err
		}
		if user.TenantID != tenantID {
			return nil, errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
		}
		return user, nil
	})
	if err != nil {
		return err
	}
	s.selfCommands = map[string]*userSelfCommand{}
	for _, action := range []string{"profile", "update_profile", "change_password"} {
		names := []string{"user"}
		if action == "profile" {
			names = append(names, "groups", "roles")
		} else if action == "update_profile" {
			names = append(names, "email")
		}
		resources := make([]app.CommandResource[userSelfInput], 0, len(names))
		for _, name := range names {
			provider, resource := s.selfProvider(name)
			policy := userSelfPolicy{}
			kind, permission := auth.KindList, "user:self:read"
			if name == "user" {
				policy.target = target
				policy.write = action != "profile"
				kind = auth.KindRead
				if policy.write {
					kind, permission = auth.KindUpdate, "user:self:write"
				}
			}
			authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource,
				Actions: []auth.Action{{Name: action + "_" + name, Kind: kind, Permission: permission}}}, ResourceAccess: auth.ResourceAccessData,
				Rules: []auth.Rule{{ID: "iam.user.self." + name, System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{policy}}}},
				auth.CompileOptions{Metadata: provider.ExecutionDescriptor().Metadata(), Checker: auth.ActionCheckerFunc(func(ctx context.Context, _ string) error {
					_, err := hostauthz.RequirePrincipal(ctx)
					return err
				})})
			if err != nil {
				return err
			}
			resourceName := name
			resources = append(resources, app.CommandResource[userSelfInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
				ConditionPath: "trusted self user -> frozen ownership/version; independent same-tenant condition before associated group/role projection or email existence; atomic conditional update",
				Intent: func(in userSelfInput) (auth.Request, error) {
					if in.ID <= 0 {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
					}
					if resourceName == "user" {
						return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
					}
					return auth.Request{}, nil
				}})
		}
		command, err := app.NewCommand(app.CommandOptions[userSelfInput, *userSelfAccess, *iamentity.User]{Resources: resources,
			Access: func(ctx context.Context, in userSelfInput, grants []*app.CommandGrant) (*userSelfAccess, error) {
				return s.bindSelf(ctx, action, in, names, target, grants)
			},
			Handler: func(ctx context.Context, in userSelfInput, access *userSelfAccess) (*iamentity.User, error) {
				return s.executeSelfAction(ctx, action, in, access, target)
			}})
		if err != nil {
			return err
		}
		s.selfCommands[action] = command
	}
	return nil
}

func (s *UserService) selfProvider(name string) (app.IExecutionDescriptorProvider, string) {
	switch name {
	case "groups":
		return s.groupRepo.Repo, svc.GroupResourceKind
	case "roles":
		return s.roleRepo.Repo, svc.RoleResourceKind
	case "email":
		return s.userRepo.Repo, svc.UserResourceKind
	default:
		return s.userRepo, svc.UserResourceKind
	}
}

func (s *UserService) bindSelf(ctx context.Context, action string, in userSelfInput, names []string, target *auth.Fact[*iamentity.User], grants []*app.CommandGrant) (*userSelfAccess, error) {
	if len(names) != len(grants) {
		return nil, errors.NewCode(errors.InvalidInput, "self action requires every resource grant")
	}
	access := &userSelfAccess{}
	var loaded *iamentity.User
	for i, name := range names {
		provider, resource := s.selfProvider(name)
		if grants[i] == nil || grants[i].Name() != name {
			return nil, errors.NewCode(errors.InvalidInput, "self resource grant differs from its declaration")
		}
		req, err := grants[i].Request()
		if err != nil {
			return nil, err
		}
		if req.Resource != resource || req.Action != action+"_"+name || name == "user" && (len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(in.ID, 10)) || name != "user" && len(req.IDs) != 0 {
			return nil, errors.NewCode(errors.InvalidInput, "self resource action or target differs from its declaration")
		}
		switch name {
		case "user":
			access.users, err = app.NewCommandRepository(s.userRepo, grants[i])
			if err == nil {
				// Associate projections are enabled only after the primary condition
				// has matched the registered target in this invocation.
				loaded, err = access.users.FromFact(ctx, target)
			}
		case "groups":
			access.groups, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, id int64, condition spec.Spec) (relations.Catalog[*iamentity.Group], error) {
				if loaded == nil || id != loaded.ID || id != in.ID {
					return relations.Catalog[*iamentity.Group]{}, errors.NewCode(errors.Forbidden, "profile group source differs from its trusted user")
				}
				return s.groupRepo.GroupsForUsers(ctx, []int64{id}, spec.And(condition, spec.Eq(meta.ByDimension("tenant"), loaded.TenantID)))
			})
		case "roles":
			access.roles, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, id int64, condition spec.Spec) (relations.Catalog[*iamentity.Role], error) {
				if loaded == nil || id != loaded.ID || id != in.ID {
					return relations.Catalog[*iamentity.Role]{}, errors.NewCode(errors.Forbidden, "profile role source differs from its trusted user")
				}
				return s.roleRepo.RolesForUsers(ctx, []int64{id}, spec.And(condition, spec.Eq(meta.ByDimension("tenant"), loaded.TenantID)))
			})
		case "email":
			access.email, err = app.NewCommandReader(provider, grants[i], func(ctx context.Context, email string, condition spec.Spec) (bool, error) {
				if loaded == nil || email == "" || email != in.Profile.Email {
					return false, errors.NewCode(errors.Forbidden, "profile email lookup differs from its frozen request")
				}
				items, err := s.userRepo.Repo.Query(ctx, query.QueryOptions{Limit: 1}, spec.And(condition,
					spec.Eq(meta.ByDimension("tenant"), loaded.TenantID), spec.Eq(meta.ByField("Email"), email)))
				return len(items) != 0 && items[0].ID != loaded.ID, err
			})
		}
		if err != nil {
			return nil, err
		}
	}
	return access, nil
}

func (s *UserService) executeSelfAction(ctx context.Context, action string, in userSelfInput, access *userSelfAccess, target *auth.Fact[*iamentity.User]) (*iamentity.User, error) {
	user, err := access.users.FromFact(ctx, target)
	if err != nil {
		return nil, err
	}
	if action == "profile" {
		groups, err := access.groups.Read(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		roles, err := access.roles.Read(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		for _, group := range groups.Items {
			user.Groups = append(user.Groups, *group)
		}
		for _, role := range roles.Items {
			user.Roles = append(user.Roles, *role)
		}
		return user, nil
	}
	if action == "change_password" {
		if !s.verifyPassword(in.Password.OldPassword, user.Password) {
			return nil, errors.NewCode(errors.Validation, "原密码错误")
		}
		if len(in.Password.NewPassword) < svc.MinPasswordLength {
			return nil, errors.NewCode(errors.Validation, "新密码长度不能少于6个字符")
		}
		user.Password, err = s.hashPassword(in.Password.NewPassword)
		if err != nil {
			return nil, errors.Wrap(err, errors.Internal, "密码加密失败")
		}
	} else {
		if in.Profile.Email != "" && in.Profile.Email != user.Email {
			used, err := access.email.Read(ctx, in.Profile.Email)
			if err != nil {
				return nil, errors.Wrap(err, errors.Database, "检查邮箱失败")
			}
			if used {
				return nil, errors.NewCode(errors.Validation, "邮箱已被使用")
			}
			user.Email = in.Profile.Email
		}
		if in.Profile.Avatar != "" {
			user.Avatar = in.Profile.Avatar
		}
	}
	user.SetUpdatedAt(time.Now())
	if err := access.users.Update(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) executeSelf(ctx context.Context, action string, in userSelfInput) (*iamentity.User, error) {
	command := s.selfCommands[action]
	if command == nil {
		return nil, errors.NewCode(errors.InvalidInput, "user self action is not declared")
	}
	return command.Execute(ctx, in)
}

// SelfAuthorizationBinding describes the actual self service also consumed by HTTP.
func (s *UserService) SelfAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.selfCommands[action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user self action is not declared")
	}
	return command.AuthorizationBinding()
}
