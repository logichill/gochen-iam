package user

import (
	"context"
	"strconv"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

type userStatusCommand = app.Command[int64, *app.CommandRepository[*iamentity.User, int64], struct{}]

// Target facts retain the write path's Forbidden result for an existing user
// outside the data condition. The same registered read supplies the snapshot
// used by CommandRepository's ownership and version protection.
type userStatusTargetPolicy struct{ target *auth.Fact[*iamentity.User] }

func (userStatusTargetPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p userStatusTargetPolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.target}
}
func (p userStatusTargetPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	if _, err := p.target.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *UserService) compileStatusCommands() error {
	target, err := auth.NewFact("iam.user.status_target", func(ctx context.Context, request auth.Request) (*iamentity.User, error) {
		if request.Resource != svc.UserResourceKind || len(request.IDs) != 1 {
			return nil, errors.NewCode(errors.InvalidInput, "user status requires one declared target")
		}
		id, err := strconv.ParseInt(request.IDs[0], 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.NewCode(errors.InvalidInput, "user status target ID must be positive")
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.statusCommands = map[string]*userStatusCommand{}
	for _, base := range []string{"activate", "deactivate", "lock", "unlock"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			var policies []auth.IPolicy
			if prefix != "" {
				policies = append(policies, userAssociationEntryPolicy{})
			}
			policies = append(policies, userStatusTargetPolicy{target})
			authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind,
				Actions: []auth.Action{{Name: action, Kind: auth.KindUpdate, Permission: svc.UserPermissionSet.Code(iamperm.ActionWrite)}}}, s.userRepo.ExecutionDescriptor().Metadata(), policies...)
			if err != nil {
				return err
			}
			command, err := app.NewCommand(app.CommandOptions[int64, *app.CommandRepository[*iamentity.User, int64], struct{}]{
				Resources: []app.CommandResource[int64]{{Name: "user", Repository: s.userRepo, Authorizer: authorizer, Action: action,
					ConditionPath: "registered target Fact -> CommandRepository.FromFact/Update -> actual user repository -> independent condition, frozen ownership and version",
					Intent: func(id int64) (auth.Request, error) {
						if id <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "user ID must be positive")
						}
						return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
					}}},
				Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (*app.CommandRepository[*iamentity.User, int64], error) {
					if len(grants) != 1 || grants[0] == nil || grants[0].Name() != "user" {
						return nil, errors.NewCode(errors.InvalidInput, "user status requires its declared grant")
					}
					request, err := grants[0].Request()
					if err != nil {
						return nil, err
					}
					if request.Resource != svc.UserResourceKind || request.Action != action || len(request.IDs) != 1 || request.IDs[0] != strconv.FormatInt(id, 10) {
						return nil, errors.NewCode(errors.InvalidInput, "user status capability differs from the declared action or target")
					}
					return app.NewCommandRepository(s.userRepo, grants[0])
				},
				Handler: func(ctx context.Context, _ int64, users *app.CommandRepository[*iamentity.User, int64]) (struct{}, error) {
					user, err := users.FromFact(ctx, target)
					if err != nil {
						return struct{}{}, err
					}
					switch base {
					case "activate":
						user.Activate()
					case "deactivate":
						user.Deactivate()
					case "lock":
						user.Lock()
					case "unlock":
						user.Unlock()
					}
					return struct{}{}, users.Update(ctx, user)
				}})
			if err != nil {
				return err
			}
			s.statusCommands[action] = command
		}
	}
	return nil
}

func (s *UserService) executeStatus(ctx context.Context, action string, id int64) error {
	command := s.statusCommands[action]
	if command == nil {
		return errors.NewCode(errors.InvalidInput, "user status action is not declared")
	}
	_, err := command.Execute(ctx, id)
	return err
}

func (s *UserService) ExecuteStatusHTTP(ctx context.Context, action string, id int64) error {
	return s.executeStatus(ctx, "http_"+action, id)
}

func (s *UserService) StatusAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.statusCommands["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "user status HTTP action is not declared")
	}
	return command.AuthorizationBinding()
}
