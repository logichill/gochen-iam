package user

import (
	"context"
	"strconv"
	"strings"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

// UserRoleAssignmentInput contains the requested role and optional grant scope.
type UserRoleAssignmentInput struct {
	UserID, RoleID int64
	GrantScopeID   *int64
}

// The binding model is stored by UserRepo and has its own execution metadata.
type userRoleBindingSource struct {
	repository *userrepo.UserRepo
	execution  app.ExecutionDescriptor
}

func (p *userRoleBindingSource) ExecutionDescriptor() app.ExecutionDescriptor { return p.execution }

type userRoleAssignmentSnapshot struct {
	User, Role userGroupTarget
	ScopeID    int64
	RoleStatus string
}

type userRoleAssignmentAccess struct {
	users        *app.CommandRepository[*iamentity.User, int64]
	roles        *app.CommandRepository[*iamentity.Role, int64]
	root         *svc.TenantScopeReader
	bindingGuard *app.CommandReader[struct{}, struct{}]
	scopeGuard   *app.CommandReader[struct{}, struct{}]
	visibility   *app.CommandReader[int64, struct{}]
	write        *app.CommandWriter[userRoleAssignmentSnapshot, struct{}]
	loaded       *userRoleAssignmentSnapshot
	trustedRole  *iamentity.Role
}

type userRoleAssignmentCommand = app.Command[UserRoleAssignmentInput, *userRoleAssignmentAccess, struct{}]

type userAssignmentRolePolicy struct{ target *auth.Fact[*iamentity.Role] }

func (userAssignmentRolePolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p userAssignmentRolePolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.target}
}
func (p userAssignmentRolePolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	role, err := p.target.Get(ctx, req)
	if err != nil {
		return auth.Decision{}, err
	}
	principal, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	if strings.EqualFold(strings.TrimSpace(role.OwnerID), "platform") && !principal.IsSystem && !tenant.CurrentContext(ctx).IsSingle() && iamauth.ActiveScopeKindFromContext(ctx) != "platform" {
		return auth.Decision{Reason: svc.ReasonPlatformScopeDenied}, nil
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *UserService) compileRoleAssignments() error {
	metadata, err := meta.Describe[*iamentity.UserRoleBinding]()
	if err != nil {
		return err
	}
	execution, err := app.BindContract(metadata, app.ResourceContract{})
	if err != nil {
		return err
	}
	s.roleBindingSource = &userRoleBindingSource{repository: s.userRepo, execution: execution}
	userFact, err := auth.NewFact("iam.user.role_assignment_user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	roleFact, err := auth.NewFact("iam.user.role_assignment_role", func(ctx context.Context, req auth.Request) (*iamentity.Role, error) {
		id, err := userGroupFactID(req, svc.RoleResourceKind)
		if err != nil {
			return nil, err
		}
		// Namespace hydration is part of the scope capability, so this fact reads
		// the actual base role repository without loading further resources.
		return s.roleRepo.Repo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.roleAssignments = map[string]*userRoleAssignmentCommand{}
	for _, action := range []string{"assign_role", "http_assign_role"} {
		var guards []auth.IPolicy
		if strings.HasPrefix(action, "http_") {
			guards = []auth.IPolicy{userAssociationEntryPolicy{}}
		}
		users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind, Actions: []auth.Action{{Name: action + "_user", Kind: auth.KindUpdate, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
			s.userRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userStatusTargetPolicy{userFact})...)
		if err != nil {
			return err
		}
		roles, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: action + "_role", Kind: auth.KindRead, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}},
			s.roleRepo.Repo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userAssignmentRolePolicy{roleFact})...)
		if err != nil {
			return err
		}
		resources := []app.CommandResource[UserRoleAssignmentInput]{
			{Name: "user", Repository: s.userRepo, Authorizer: users, Action: action + "_user",
				ConditionPath: "trusted User Fact -> CommandRepository.FromFact -> independent user condition -> transaction recheck and frozen ownership/version",
				Intent: func(in UserRoleAssignmentInput) (auth.Request, error) {
					if in.UserID <= 0 || in.RoleID <= 0 {
						return auth.Request{}, errors.NewCode(errors.InvalidInput, "user and role IDs must be positive")
					}
					return auth.Request{IDs: []string{strconv.FormatInt(in.UserID, 10)}}, nil
				}},
			{Name: "role", Repository: s.roleRepo.Repo, Authorizer: roles, Action: action + "_role",
				ConditionPath: "trusted base Role Fact -> platform owner constraint -> CommandRepository.FromFact -> independent namespace condition and transaction recheck",
				Intent: func(in UserRoleAssignmentInput) (auth.Request, error) {
					return auth.Request{IDs: []string{strconv.FormatInt(in.RoleID, 10)}}, nil
				}}}
		resource, err := s.roleAssignmentResource(action, "binding", s.roleBindingSource, auth.KindCreate, guards)
		if err != nil {
			return err
		}
		resources = append(resources, resource)
		if s.scopeAuthorizer != nil {
			tenantProvider, scopeProvider, err := s.scopeAuthorizer.TenantScopeProviders()
			if err != nil {
				return err
			}
			for _, target := range []struct {
				name     string
				provider app.IExecutionDescriptorProvider
			}{{"scope", scopeProvider}, {"visibility", scopeProvider}, {"tenant", tenantProvider}, {"root", scopeProvider}} {
				resource, err := s.roleAssignmentResource(action, target.name, target.provider, auth.KindRead, guards)
				if err != nil {
					return err
				}
				if target.name == "tenant" || target.name == "root" {
					resource.When = func(ctx context.Context, _ UserRoleAssignmentInput, _ []*app.CommandGrant) (bool, error) {
						return tenant.CurrentContext(ctx).IsSingle(), nil
					}
				}
				resources = append(resources, resource)
			}
		}
		command, err := app.NewCommand(app.CommandOptions[UserRoleAssignmentInput, *userRoleAssignmentAccess, struct{}]{Resources: resources,
			Access: func(ctx context.Context, in UserRoleAssignmentInput, grants []*app.CommandGrant) (*userRoleAssignmentAccess, error) {
				return s.bindRoleAssignment(ctx, action, in, grants)
			},
			Handler: func(ctx context.Context, in UserRoleAssignmentInput, access *userRoleAssignmentAccess) (struct{}, error) {
				if _, err := access.bindingGuard.Read(ctx, struct{}{}); err != nil {
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
				if user.TenantID != role.TenantID {
					return struct{}{}, errors.NewCode(errors.Forbidden, "user and role must belong to the same tenant")
				}
				if role.Status != svc.RoleStatusActive {
					return struct{}{}, errors.NewCode(errors.Validation, "只能分配激活状态的角色")
				}
				scopeID := role.NamespaceScopeID
				if tenant.CurrentContext(ctx).IsSingle() {
					if access.root == nil {
						return struct{}{}, errors.NewCode(errors.Dependency, "single tenant authorization requires scope authorizer")
					}
					root, err := access.root.Read(ctx)
					if err != nil {
						return struct{}{}, err
					}
					scopeID = root.ID
					if in.GrantScopeID != nil && *in.GrantScopeID > 0 && *in.GrantScopeID != scopeID {
						return struct{}{}, errors.NewCode(errors.InvalidInput, "single tenant role binding must target tenant root scope")
					}
				} else {
					if activeID := svc.ManagedScopeIDFromContext(ctx); activeID > 0 {
						scopeID = activeID
					}
					if in.GrantScopeID != nil && *in.GrantScopeID > 0 {
						scopeID = *in.GrantScopeID
					}
				}
				access.trustedRole = role
				access.loaded = &userRoleAssignmentSnapshot{
					User:    userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID},
					Role:    userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID},
					ScopeID: scopeID, RoleStatus: role.Status,
				}
				if err := access.checkScope(ctx); err != nil {
					return struct{}{}, err
				}
				return access.write.Write(ctx, *access.loaded)
			}})
		if err != nil {
			return err
		}
		s.roleAssignments[action] = command
	}
	return nil
}

func (s *UserService) roleAssignmentResource(action, name string, provider app.IExecutionDescriptorProvider, kind auth.Kind, guards []auth.IPolicy) (app.CommandResource[UserRoleAssignmentInput], error) {
	authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.role_assignment." + name,
		Actions: []auth.Action{{Name: action + "_" + name, Kind: kind, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}}, ResourceAccess: auth.ResourceAccessData,
		Rules: []auth.Rule{{ID: "iam.user.role_assignment." + name, System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}},
		auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
	return app.CommandResource[UserRoleAssignmentInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
		ConditionPath: "CommandReader/Writer -> trusted user/role and chosen grant scope -> native binding, scope or visibility operation; complete predicate catalog before native reads",
		Intent:        func(UserRoleAssignmentInput) (auth.Request, error) { return auth.Request{}, nil }}, err
}

func (a *userRoleAssignmentAccess) checkScope(ctx context.Context) error {
	if a.loaded == nil || a.loaded.ScopeID <= 0 {
		return errors.NewCode(errors.InvalidInput, "grant scope is required")
	}
	if a.scopeGuard != nil {
		if _, err := a.scopeGuard.Read(ctx, struct{}{}); err != nil {
			return err
		}
		_, err := a.visibility.Read(ctx, a.loaded.ScopeID)
		return err
	}
	return nil
}

func (s *UserService) executeRoleAssignment(ctx context.Context, action string, in UserRoleAssignmentInput) error {
	command := s.roleAssignments[action]
	if command == nil {
		return errors.NewCode(errors.InvalidInput, "user role assignment action is not declared")
	}
	_, err := command.Execute(ctx, in)
	return err
}

func (s *UserService) ExecuteRoleAssignmentHTTP(ctx context.Context, in UserRoleAssignmentInput) error {
	return s.executeRoleAssignment(ctx, "http_assign_role", in)
}

func (s *UserService) RoleAssignmentAuthorizationBinding() (auth.EntryBinding, error) {
	command := s.roleAssignments["http_assign_role"]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user role assignment HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
