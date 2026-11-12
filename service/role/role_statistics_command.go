package role

import (
	"context"
	iamperm "gochen-iam/permissions"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type roleReadCoverage struct{ TenantID string }

type roleStatisticsPolicy struct {
	coverage *auth.Fact[roleReadCoverage]
	http     bool
}

func (p roleStatisticsPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (p roleStatisticsPolicy) FactSources() []auth.IFactSource {
	return []auth.IFactSource{p.coverage}
}
func (p roleStatisticsPolicy) Evaluate(ctx context.Context, req auth.Request) (auth.Decision, error) {
	_, err := hostauthz.RequirePrincipal(ctx)
	if err != nil {
		return auth.Decision{}, err
	}
	if p.http {
		if _, err := (roleHTTPEntryPolicy{}).Evaluate(ctx, req); err != nil {
			return auth.Decision{}, err
		}
	}
	if _, err := p.coverage.Get(ctx, req); err != nil {
		return auth.Decision{}, err
	}
	// Preserve explicit scopes (including System) and the default trusted
	// ActiveScopeID projection used by the existing statistics implementation.
	condition, err := roleReadSpec(ctx)
	return auth.Decision{Allowed: true, Spec: condition}, err
}

type roleStatisticsAccess struct {
	roles *app.CommandReader[struct{}, map[string]interface{}]
}
type roleStatisticsCommand = app.Command[struct{}, roleStatisticsAccess, map[string]interface{}]

func (s *RoleService) compileStatisticsCommands() error {
	if s.scopeAuthorizer != nil {
		if _, _, err := s.scopeAuthorizer.TenantScopeProviders(); err != nil {
			return err
		}
	}
	coverage, err := auth.NewFact("iam.role.statistics_coverage", func(ctx context.Context, _ auth.Request) (roleReadCoverage, error) {
		key, err := svc.TenantIDFromContext(ctx)
		if err != nil {
			return roleReadCoverage{}, err
		}
		if s.scopeAuthorizer == nil || tenant.CurrentContext(ctx).IsSingle() {
			return roleReadCoverage{TenantID: key}, nil
		}
		key, err = svc.RequireTenantMatch(ctx, key)
		if err != nil {
			return roleReadCoverage{}, err
		}
		tenantCtx, err := svc.BindTenantContext(ctx, key)
		if err != nil {
			return roleReadCoverage{}, err
		}
		root, err := s.scopeAuthorizer.ResolveTenantScope(tenantCtx, key)
		if err != nil {
			return roleReadCoverage{}, err
		}
		active, err := s.scopeAuthorizer.ResolveActiveScope(ctx)
		if err != nil {
			return roleReadCoverage{}, err
		}
		covers, err := s.scopeAuthorizer.ScopeCovers(ctx, active.ID, root.ID)
		if err != nil {
			return roleReadCoverage{}, err
		}
		if !covers {
			return roleReadCoverage{}, errors.NewCode(errors.Forbidden, "当前授权域不覆盖目标资源")
		}
		return roleReadCoverage{TenantID: key}, nil
	})
	if err != nil {
		return err
	}
	s.statisticsCommands = map[string]*roleStatisticsCommand{}
	for _, action := range []string{"statistics", "http_statistics"} {
		descriptor := auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: action, Kind: auth.KindList, Permission: svc.RolePermissionSet.Code(iamperm.ActionRead)}}}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: descriptor, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "iam.role.statistics", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{roleStatisticsPolicy{coverage: coverage, http: action == "http_statistics"}}}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: s.roleRepo.Repo.ExecutionDescriptor().Metadata()})
		if err != nil {
			return err
		}
		command, err := app.NewCommand(app.CommandOptions[struct{}, roleStatisticsAccess, map[string]interface{}]{
			Resources: []app.CommandResource[struct{}]{{Name: "roles", Repository: s.roleRepo.Repo, Authorizer: authorizer, Action: action,
				ConditionPath: "CommandReader -> base Role QueryCount and CountByStatus; condition before every count and status page, without user/group/namespace hydration",
				Intent:        func(struct{}) (auth.Request, error) { return auth.Request{}, nil }}},
			Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (roleStatisticsAccess, error) {
				return s.bindStatisticsAccess(action, grants)
			}, Handler: func(ctx context.Context, _ struct{}, access roleStatisticsAccess) (map[string]interface{}, error) {
				return access.roles.Read(ctx, struct{}{})
			}})
		if err != nil {
			return err
		}
		s.statisticsCommands[action] = command
	}
	return nil
}

func (s *RoleService) bindStatisticsAccess(action string, grants []*app.CommandGrant) (roleStatisticsAccess, error) {
	var access roleStatisticsAccess
	if len(grants) != 1 || grants[0] == nil || grants[0].Name() != "roles" {
		return access, errors.NewCode(errors.InvalidInput, "role statistics requires its declared role grant")
	}
	request, err := grants[0].Request()
	if err != nil {
		return access, err
	}
	if request.Resource != svc.RoleResourceKind || request.Action != action || len(request.IDs) != 0 || len(request.Targets) != 0 {
		return access, errors.NewCode(errors.InvalidInput, "role statistics request differs from its declaration")
	}
	access.roles, err = app.NewCommandReader(s.roleRepo.Repo, grants[0], func(ctx context.Context, _ struct{}, condition spec.Spec) (map[string]interface{}, error) {
		total, err := s.roleRepo.Repo.QueryCount(ctx, query.QueryOptions{}, condition)
		if err != nil {
			return nil, err
		}
		active, err := s.roleRepo.Repo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("Status"), svc.RoleStatusActive)))
		if err != nil {
			return nil, err
		}
		system, err := s.roleRepo.Repo.QueryCount(ctx, query.QueryOptions{}, spec.And(condition, spec.Eq(meta.ByField("IsSystem"), true)))
		if err != nil {
			return nil, err
		}
		statuses, err := s.roleRepo.CountByStatus(ctx, condition)
		return map[string]interface{}{"total_roles": total, "active_roles": int(active), "system_roles": int(system), "roles_by_status": statuses}, err
	})
	return access, err
}

func (s *RoleService) RoleStatisticsHTTP(ctx context.Context) (map[string]interface{}, error) {
	return s.statisticsCommands["http_statistics"].Execute(ctx, struct{}{})
}

func (s *RoleService) StatisticsAuthorizationBinding() (auth.EntryBinding, error) {
	if s == nil || s.statisticsCommands["http_statistics"] == nil {
		return auth.EntryBinding{}, errors.NewCode(errors.InvalidInput, "role statistics requires its constructed command")
	}
	return s.statisticsCommands["http_statistics"].AuthorizationBinding()
}
