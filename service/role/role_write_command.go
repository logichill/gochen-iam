package role

import (
	"context"
	"strconv"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
)

// RoleWriteInput identifies one role and the permission removal intent.
type RoleWriteInput struct {
	ID         int64
	Permission string
}
type roleWriteCommand = app.Command[RoleWriteInput, *app.CommandRepository[*iamentity.Role, int64], struct{}]

type roleHTTPEntryPolicy struct{}

func (roleHTTPEntryPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (roleHTTPEntryPolicy) Evaluate(ctx context.Context, _ auth.Request) (auth.Decision, error) {
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
	if !principal.AllowsPermission(svc.RolePermissionSet.Code(iamperm.ActionManage)) {
		return auth.Decision{}, errors.NewCode(errors.Forbidden, "权限不足")
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

type roleWriteTargetPolicy struct{ target *auth.Fact[*iamentity.Role] }

func (roleWriteTargetPolicy) Vocabulary() auth.Vocabulary { return auth.Vocabulary{} }
func (p roleWriteTargetPolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.target}
}
func (p roleWriteTargetPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	if _, err := p.target.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	return auth.Decision{Allowed: true, Spec: spec.All()}, nil
}

func (s *RoleService) compileWriteCommands() error {
	target, err := auth.NewFact("iam.role.write_target", func(ctx context.Context, req auth.Request) (*iamentity.Role, error) {
		if req.Resource != svc.RoleResourceKind || len(req.IDs) != 1 {
			return nil, errors.NewCode(errors.InvalidInput, "role write requires one declared target")
		}
		id, err := strconv.ParseInt(req.IDs[0], 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.NewCode(errors.InvalidInput, "role ID must be positive")
		}
		return s.roleRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		return err
	}
	s.writeCommands = map[string]*roleWriteCommand{}
	for _, base := range []string{"activate", "deactivate", "remove_permission"} {
		for _, prefix := range []string{"", "http_"} {
			action := prefix + base
			constraints := []auth.IPolicy{}
			if prefix != "" {
				constraints = append(constraints, roleHTTPEntryPolicy{})
			}
			constraints = append(constraints, roleWriteTargetPolicy{target})
			authorizer, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind,
				Actions: []auth.Action{{Name: action, Kind: auth.KindUpdate, Permission: svc.RolePermissionSet.Code(iamperm.ActionWrite)}}},
				s.roleRepo.ExecutionDescriptor().Metadata(), constraints...)
			if err != nil {
				return err
			}
			command, err := app.NewCommand(app.CommandOptions[RoleWriteInput, *app.CommandRepository[*iamentity.Role, int64], struct{}]{
				Resources: []app.CommandResource[RoleWriteInput]{{Name: "role", Repository: s.roleRepo, Authorizer: authorizer, Action: action,
					ConditionPath: "registered actual Role Fact -> CommandRepository.FromFact/Update -> independent scope condition, frozen ownership/version and atomic RoleRepo update",
					Intent: func(in RoleWriteInput) (auth.Request, error) {
						if in.ID <= 0 {
							return auth.Request{}, errors.NewCode(errors.InvalidInput, "role ID must be positive")
						}
						return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
					}}},
				Access: func(_ context.Context, in RoleWriteInput, grants []*app.CommandGrant) (*app.CommandRepository[*iamentity.Role, int64], error) {
					return s.bindWrite(action, in, grants)
				},
				Handler: func(ctx context.Context, in RoleWriteInput, roles *app.CommandRepository[*iamentity.Role, int64]) (struct{}, error) {
					role, err := roles.FromFact(ctx, target)
					if err != nil {
						return struct{}{}, err
					}
					switch base {
					case "activate":
						role.Activate()
					case "deactivate":
						if role.IsSystem {
							return struct{}{}, errors.NewCode(errors.Validation, "系统角色不能被停用")
						}
						role.Deactivate()
					case "remove_permission":
						if role.IsSystem {
							return struct{}{}, errors.NewCode(errors.Validation, "系统角色权限不能被修改")
						}
						role.RemovePermission(in.Permission)
					}
					return struct{}{}, roles.Update(ctx, role)
				}})
			if err != nil {
				return err
			}
			s.writeCommands[action] = command
		}
	}
	return nil
}

func (s *RoleService) bindWrite(action string, in RoleWriteInput, grants []*app.CommandGrant) (*app.CommandRepository[*iamentity.Role, int64], error) {
	if len(grants) != 1 || grants[0] == nil || grants[0].Name() != "role" {
		return nil, errors.NewCode(errors.InvalidInput, "role write requires its declared grant")
	}
	req, err := grants[0].Request()
	if err != nil {
		return nil, err
	}
	if req.Resource != svc.RoleResourceKind || req.Action != action || len(req.IDs) != 1 || req.IDs[0] != strconv.FormatInt(in.ID, 10) || len(req.Targets) != 0 {
		return nil, errors.NewCode(errors.InvalidInput, "role write action or target differs from its declaration")
	}
	return app.NewCommandRepository(s.roleRepo, grants[0])
}

func (s *RoleService) executeWrite(ctx context.Context, action string, in RoleWriteInput) error {
	command := s.writeCommands[action]
	if command == nil {
		return errors.NewCode(errors.InvalidInput, "role write action is not declared")
	}
	_, err := command.Execute(ctx, in)
	return err
}

func (s *RoleService) ExecuteWriteHTTP(ctx context.Context, action string, in RoleWriteInput) error {
	return s.executeWrite(ctx, "http_"+action, in)
}

func (s *RoleService) WriteAuthorizationBinding(action string) (auth.EntryBinding, error) {
	command := s.writeCommands["http_"+action]
	if command == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "role HTTP write action is not declared")
	}
	return command.AuthorizationBinding()
}
