package role

import (
	"context"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleMemberScopePolicy struct{}

func (roleMemberScopePolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (roleMemberScopePolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
	condition, err := roleReadSpec(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	return auth.Decision{Allowed: true, Spec: condition}, nil
}

type roleUsersSourcePolicy struct {
	service *RoleService
	target  *auth.Fact[*iamentity.Role]
}

func (p roleUsersSourcePolicy) FactSources() []auth.IFactSource { return []auth.IFactSource{p.target} }

func (roleUsersSourcePolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p roleUsersSourcePolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	role, err := p.target.Get(ctx, req)
	if err != nil {
		return auth.Decision{}, err
	}
	if err := svc.RequireAuthorization(ctx, p.service.authorizer, "role:api:read", role); err != nil {
		return auth.Decision{}, err
	}
	// The source role retains its existing target-authorization semantics. Its
	// members and their nested projections apply independent data-scope queries.
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *RoleService) CustomAuthorizationBinding(action string) (auth.EntryBinding, error) {
	if action == "users" {
		return s.usersCommand.AuthorizationBinding()
	}
	if action == "groups" {
		return s.groupsCommand.AuthorizationBinding()
	}
	if command := s.userCommands[action]; command != nil {
		return command.AuthorizationBinding()
	}
	if action == "permissions" {
		return s.permissionsCommand.AuthorizationBinding()
	}
	if action == "initialize" {
		return s.initializeCommand.AuthorizationBinding()
	}
	if action == "add_permission" {
		command, err := s.crudApplication.command("update", nil)
		if err != nil {
			return auth.EntryBinding{}, err
		}
		return command.AuthorizationBinding()
	}
	if action == "clone" {
		command, err := s.crudApplication.cloneCommand()
		if err != nil {
			return auth.EntryBinding{}, err
		}
		return command.AuthorizationBinding()
	}
	return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "role custom action is not declared")
}

func (s *RoleService) RolePermissions(ctx context.Context, id int64) (iamentity.PermissionArray, error) {
	return s.permissionsCommand.Execute(ctx, id)
}

func matchRoleCondition(condition spec.Spec, role *iamentity.Role) error {
	ok, err := spec.NewInterpreter().Match(condition, role)
	if err != nil {
		return err
	}
	if !ok {
		return errors.NewCode(errors.Forbidden, "role is outside the declared scope")
	}
	return nil
}
