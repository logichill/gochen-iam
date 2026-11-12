package user

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

// UserRoleBindingInput identifies a direct binding owned by the requested user.
type UserRoleBindingInput struct{ UserID, BindingID int64 }
type userRoleBindingSelectAccess struct {
	user    *app.CommandRepository[*iamentity.User, int64]
	binding *app.CommandReader[int64, *userrepo.BindingRecord]
}
type userRoleBindingSelectCommand = app.Command[UserRoleBindingInput, *userRoleBindingSelectAccess, *userrepo.BindingRecord]

func (s *UserService) compileRoleBindingSelectors() error {
	target, err := auth.NewFact("iam.user.role_binding_select_user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.bindingSelectors = map[string]*userRoleBindingSelectCommand{}
	for _, action := range []string{"select_binding", "http_select_binding"} {
		var guards []auth.IPolicy
		if strings.HasPrefix(action, "http_") {
			guards = []auth.IPolicy{userAssociationEntryPolicy{}}
		}
		users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind, Actions: []auth.Action{{Name: action + "_user", Kind: auth.KindRead, Permission: "user:api:write"}}},
			s.userRepo.ExecutionDescriptor().Metadata(), append(append([]auth.IPolicy(nil), guards...), userStatusTargetPolicy{target})...)
		if err != nil {
			return err
		}
		bindings, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.role_binding_select.binding", Actions: []auth.Action{{Name: action + "_binding", Kind: auth.KindRead, Permission: "user:api:write"}}},
			ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{ID: "iam.user.role_binding_select.binding", System: auth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: guards}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: s.roleBindingSource.ExecutionDescriptor().Metadata()})
		if err != nil {
			return err
		}
		command, err := app.NewCommand(app.CommandOptions[UserRoleBindingInput, *userRoleBindingSelectAccess, *userrepo.BindingRecord]{
			Resources: []app.CommandResource[UserRoleBindingInput]{
				{Name: "user", Repository: s.userRepo, Authorizer: users, Action: action + "_user",
					ConditionPath: "trusted User Fact -> independent user predicate -> binding selection for this authorized user",
					Intent: func(in UserRoleBindingInput) (auth.Request, error) {
						if in.UserID <= 0 || in.BindingID <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "user and binding IDs must be positive")
						}
						return auth.Request{IDs: []string{strconv.FormatInt(in.UserID, 10)}}, nil
					}},
				{Name: "binding", Repository: s.roleBindingSource, Authorizer: bindings, Action: action + "_binding",
					ConditionPath: "complete binding predicate -> requested binding ID -> verify actual UserID -> trusted role/grant snapshot for the deletion command",
					Intent:        func(UserRoleBindingInput) (auth.Request, error) { return auth.Request{}, nil }},
			},
			Access: func(ctx context.Context, in UserRoleBindingInput, grants []*app.CommandGrant) (*userRoleBindingSelectAccess, error) {
				if len(grants) != 2 {
					return nil, errors.NewCode(errors.InvalidInput, "binding selection requires both resource grants")
				}
				for i, name := range []string{"user", "binding"} {
					if grants[i] == nil || grants[i].Name() != name {
						return nil, errors.NewCode(errors.InvalidInput, "binding selection grant differs from its declaration")
					}
					req, err := grants[i].Request()
					if err != nil {
						return nil, err
					}
					resource := "iam.user.role_binding_select.binding"
					if i == 0 {
						resource = svc.UserResourceKind
					}
					if req.Resource != resource || req.Action != action+"_"+name || i == 0 && (len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(in.UserID, 10)) || i == 1 && len(req.IDs) != 0 {
						return nil, errors.NewCode(errors.InvalidInput, "binding selection differs from the declared action or target")
					}
				}
				a := &userRoleBindingSelectAccess{}
				var err error
				a.user, err = app.NewCommandRepository(s.userRepo, grants[0])
				if err != nil {
					return nil, err
				}
				known := false
				a.binding, err = app.NewCommandReader(s.roleBindingSource, grants[1], func(ctx context.Context, id int64, condition spec.Spec) (*userrepo.BindingRecord, error) {
					if err := requireRoleAssignmentCatalog(condition); err != nil {
						return nil, err
					}
					if !known || id != in.BindingID {
						return nil, errors.NewCode(errors.Forbidden, "binding selection requires its authorized user and frozen binding ID")
					}
					binding, err := s.userRepo.GetRoleBinding(ctx, id)
					if err != nil {
						return nil, err
					}
					if binding.BindingID != in.BindingID || binding.UserID != in.UserID {
						return nil, errors.NewCode(errors.Forbidden, "角色绑定与目标用户不匹配")
					}
					return binding, nil
				})
				if err != nil {
					return nil, err
				}
				// Loading the user through this capability applies its independent
				// predicate before a binding record can be selected.
				if _, err := a.user.FromFact(ctx, target); err != nil {
					return nil, err
				}
				known = true
				return a, nil
			},
			Handler: func(ctx context.Context, in UserRoleBindingInput, a *userRoleBindingSelectAccess) (*userrepo.BindingRecord, error) {
				return a.binding.Read(ctx, in.BindingID)
			},
		})
		if err != nil {
			return err
		}
		s.bindingSelectors[action] = command
	}
	return nil
}
