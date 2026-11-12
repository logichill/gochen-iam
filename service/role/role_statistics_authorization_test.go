package role

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func roleStatisticsPrincipal(t *testing.T, tenantID, subject, kind string, permissions ...string) context.Context {
	t.Helper()
	ctx, err := contextx.WithTenantID(t.Context(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: subject, ActiveScopeID: 1, Permissions: permissions})
	if err != nil {
		t.Fatal(err)
	}
	return iamauth.BindActiveScopeContext(ctx, 1, kind)
}

func TestRoleStatisticsRejectsBeforeBusinessAndCoverageQueries(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	scopes, err := scoperepo.NewScopeRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenantrepo.NewTenantRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	resolver := svc.NewScopeAuthorizer(scopes, tenants)
	service, err := NewRoleService(env.roleRepo, env.roleService.userRepo, env.roleService.groupRepo, resolver, svc.NewIAMAccess(resolver), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("role:statistics:denial", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err = contextx.WithUserID(trace, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{
		{nil, errors.InvalidInput}, {trace, errors.Unauthorized},
		{roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:write"), errors.Forbidden},
	} {
		if _, err := service.RoleStatistics(test.ctx); !errors.Is(err, test.code) {
			t.Fatalf("ordinary denial=%v, want %s", err, test.code)
		}
	}
	for _, test := range []struct {
		subject, kind string
		permissions   []string
		code          errors.ErrorCode
	}{
		{"7", "tenant", []string{"role:api:read"}, errors.Forbidden},
		{"7", "department", []string{"role:api:read", "role:api:manage"}, errors.Forbidden},
		{"trace", "tenant", []string{"role:api:read", "role:api:manage"}, errors.Unauthorized},
	} {
		ctx := roleStatisticsPrincipal(t, env.tenantID, test.subject, test.kind, test.permissions...)
		if _, err := service.RoleStatisticsHTTP(ctx); !errors.Is(err, test.code) {
			t.Fatalf("HTTP denial=%v, want %s", err, test.code)
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("denied statistics performed %d business/fact queries", reads.Load())
	}
}

func TestRoleStatisticsPreservesDefaultScopeAndExplicitSystemScope(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	now := time.Now()
	roles := []iamentity.Role{
		{TenantID: env.tenantID, NamespaceScopeID: 1, Name: "visible", Status: "active", IsSystem: true},
		{TenantID: env.tenantID, NamespaceScopeID: 2, Name: "hidden", Status: "inactive"},
		{TenantID: "other", NamespaceScopeID: 1, Name: "other", Status: "active"},
		{TenantID: env.tenantID, NamespaceScopeID: 1, Name: "deleted", Status: "active", DeletedAt: &now},
	}
	if err := env.db.Create(&roles).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:read", "role:api:manage")
	for _, read := range []func(context.Context) (map[string]interface{}, error){env.roleService.RoleStatistics, env.roleService.RoleStatisticsHTTP} {
		stats, err := read(ctx)
		if err != nil || stats["total_roles"] != int64(1) || stats["active_roles"] != 1 || stats["system_roles"] != 1 {
			t.Fatalf("default ActiveScopeID projection=%v error=%v", stats, err)
		}
	}
	system, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{IsSystem: true, ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := env.roleService.RoleStatistics(system)
	if err != nil || stats["total_roles"] != int64(2) {
		t.Fatalf("default System scope=%v error=%v", stats, err)
	}
	system, err = scoped.WithDataScope(system, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	stats, err = env.roleService.RoleStatistics(system)
	if err != nil || stats["total_roles"] != int64(1) {
		t.Fatalf("explicit System scope=%v error=%v", stats, err)
	}
	ctx = tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "department")
	if _, err := env.roleService.RoleStatisticsHTTP(ctx); err != nil {
		t.Fatalf("single-tenant HTTP scope exemption=%v", err)
	}
}

func TestRoleStatisticsSystemRetainsCoverageAndMissingRootStaysReadOnly(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	if err := env.db.AutoMigrate(&iamentity.Tenant{}); err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenantrepo.NewTenantRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	rootID := int64(1)
	for _, value := range []any{
		&iamentity.Scope{ID: 1, Key: "tenant:" + env.tenantID, Type: "tenant", Name: "root", Path: "/root/"},
		&iamentity.Scope{ID: 2, Key: "outside", Type: "region", Name: "outside", Path: "/outside/"},
		&iamentity.ScopeVisibility{ViewerScopeID: 1, TargetScopeID: 1},
		&iamentity.Tenant{Key: env.tenantID, Name: "tenant", RootScopeID: &rootID, Status: "active"},
	} {
		if err := env.db.Create(value).Error; err != nil {
			t.Fatal(err)
		}
	}
	resolver := svc.NewScopeAuthorizer(scopes, tenants)
	service, err := NewRoleService(env.roleRepo, env.roleService.userRepo, env.roleService.groupRepo, resolver, svc.NewIAMAccess(resolver), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(env.backgroundCtx, hostauthz.Principal{IsSystem: true, ActiveScopeID: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 2, "region")
	if _, err := service.RoleStatistics(ctx); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("System outside coverage=%v", err)
	}
	ctx, err = hostauthz.WithPrincipal(env.backgroundCtx, hostauthz.Principal{IsSystem: true, ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
	if _, err := service.RoleStatistics(ctx); err != nil {
		t.Fatalf("System inside coverage=%v", err)
	}
	if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", env.tenantID).UpdateColumn("root_scope_id", nil).Error; err != nil {
		t.Fatal(err)
	}
	writes := &atomic.Int64{}
	if err := env.db.Callback().Create().Before("gorm:create").Register("role:statistics:create", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("role:statistics:update", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RoleStatistics(ctx); !errors.Is(err, errors.Internal) || writes.Load() != 0 {
		t.Fatalf("missing root error=%v provisioning writes=%d", err, writes.Load())
	}
}

func TestRoleStatisticsConditionsApplyToEveryCountAndStatusPage(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	roles := make([]iamentity.Role, 0, 2003)
	for i := 0; i < 2003; i++ {
		scopeID := int64(2)
		if i%2 == 0 {
			scopeID = 1
		}
		roles = append(roles, iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: scopeID, Name: fmt.Sprintf("page-%d", i), Status: "active", IsSystem: i%4 == 0})
	}
	if err := env.db.CreateInBatches(&roles, 100).Error; err != nil {
		t.Fatal(err)
	}
	counts, pages := 0, 0
	if err := env.db.Callback().Query().After("gorm:query").Register("role:statistics:pages", func(tx *gorm.DB) {
		if tx.Statement.Table != "roles" {
			t.Errorf("statistics hydrated undeclared table %s", tx.Statement.Table)
			return
		}
		sql := tx.Statement.SQL.String()
		if !strings.Contains(sql, "namespace_scope_id") {
			t.Errorf("query did not execute scope condition: %s", sql)
		}
		if strings.Contains(sql, "count(*)") {
			counts++
		} else {
			pages++
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:read")
	stats, err := env.roleService.RoleStatistics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["total_roles"] != int64(1002) || stats["active_roles"] != 1002 || stats["system_roles"] != 501 || stats["roles_by_status"].(map[string]int64)["active"] != 1002 {
		t.Fatalf("count/status condition mismatch=%v", stats)
	}
	if counts != 3 || pages != 2 {
		t.Fatalf("count queries=%d status pages=%d, want 3/2", counts, pages)
	}
}

type roleStatisticsConditionPolicy struct {
	condition spec.Spec
	deny      bool
}

func (p roleStatisticsConditionPolicy) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ID()}}
}
func (p roleStatisticsConditionPolicy) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: !p.deny, Spec: p.condition}, nil
}

func TestRoleStatisticsCapabilityKeepsIndependentConditionSourceAndLifetime(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	first := env.createTestRole(t, "first")
	env.createTestRole(t, "second")
	ctx := roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:read")
	other, err := rolerepo.NewRoleRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	var retained roleStatisticsAccess
	for _, deny := range []bool{false, true} {
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "statistics", Kind: auth.KindList, Permission: "role:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{roleStatisticsConditionPolicy{spec.In(meta.ID(), first.ID), deny}}}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: env.roleRepo.Repo.ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		command, err := app.NewCommand(app.CommandOptions[struct{}, roleStatisticsAccess, map[string]interface{}]{
			Resources: []app.CommandResource[struct{}]{{Name: "roles", Repository: env.roleRepo.Repo, Authorizer: authorizer, Action: "statistics", Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil }}},
			Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (roleStatisticsAccess, error) {
				if _, err := env.roleService.bindStatisticsAccess("statistics", nil); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("missing grant=%v", err)
				}
				if _, err := env.roleService.bindStatisticsAccess("http_statistics", grants); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("wrong action=%v", err)
				}
				changed := *env.roleService
				changed.roleRepo = other
				if _, err := changed.bindStatisticsAccess("statistics", grants); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("replaced source=%v", err)
				}
				return env.roleService.bindStatisticsAccess("statistics", grants)
			}, Handler: func(ctx context.Context, _ struct{}, access roleStatisticsAccess) (map[string]interface{}, error) {
				retained = access
				changed, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"role:api:read"}})
				if err != nil {
					return nil, err
				}
				if _, err := access.roles.Read(changed, struct{}{}); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("changed identity=%v", err)
				}
				changed, err = contextx.WithTenantID(ctx, "other")
				if err != nil {
					return nil, err
				}
				if _, err := access.roles.Read(changed, struct{}{}); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("changed tenant=%v", err)
				}
				return access.roles.Read(ctx, struct{}{})
			}})
		if err != nil {
			t.Fatal(err)
		}
		reads := &atomic.Int64{}
		if err := env.db.Callback().Query().Before("gorm:query").Register(fmt.Sprintf("role:statistics:capability:%t", deny), func(*gorm.DB) { reads.Add(1) }); err != nil {
			t.Fatal(err)
		}
		stats, err := command.Execute(ctx, struct{}{})
		if deny {
			if !errors.Is(err, errors.Forbidden) || reads.Load() != 0 {
				t.Fatalf("denial=%v reads=%d", err, reads.Load())
			}
			continue
		}
		if err != nil || stats["total_roles"] != int64(1) || stats["roles_by_status"].(map[string]int64)["active"] != 1 {
			t.Fatalf("independent In condition=%v error=%v", stats, err)
		}
		if _, err := retained.roles.Read(ctx, struct{}{}); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("expired capability=%v", err)
		}
	}
}

func TestRoleStatisticsConstructorRequiresActualProvidersAndFreezesThem(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	s := env.roleService
	for _, construct := range []func() error{
		func() error {
			_, err := NewRoleService(nil, s.userRepo, s.groupRepo, nil, s.authorizer, nil, nil, nil)
			return err
		},
		func() error {
			_, err := NewRoleService(&rolerepo.RoleRepo{}, s.userRepo, s.groupRepo, nil, s.authorizer, nil, nil, nil)
			return err
		},
		func() error {
			_, err := NewRoleService(s.roleRepo, nil, s.groupRepo, nil, s.authorizer, nil, nil, nil)
			return err
		},
		func() error {
			_, err := NewRoleService(s.roleRepo, s.userRepo, nil, nil, s.authorizer, nil, nil, nil)
			return err
		},
		func() error {
			_, err := NewRoleService(s.roleRepo, s.userRepo, s.groupRepo, nil, nil, nil, nil, nil)
			return err
		},
		func() error {
			_, err := NewRoleService(s.roleRepo, s.userRepo, s.groupRepo, svc.NewScopeAuthorizer(nil, nil), s.authorizer, nil, nil, nil)
			return err
		},
	} {
		if err := construct(); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("invalid construction=%v", err)
		}
	}
	env.createTestRole(t, "frozen")
	s.roleRepo, s.scopeAuthorizer = nil, svc.NewScopeAuthorizer(nil, nil)
	stats, err := s.RoleStatistics(env.backgroundCtx)
	if err != nil || stats["total_roles"] != int64(1) {
		t.Fatalf("provider replacement changed compiled execution=%v error=%v", stats, err)
	}
}
