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
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestRoleSystemDirectoryRejectsBeforeAnyQuery(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	reads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("role:system:denial", func(*gorm.DB) { reads.Add(1) }); err != nil {
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
	}{{nil, errors.InvalidInput}, {trace, errors.Unauthorized},
		{roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:write"), errors.Forbidden}} {
		if _, err := env.roleService.SystemRoles(test.ctx); !errors.Is(err, test.code) {
			t.Fatalf("ordinary denial=%v want=%s", err, test.code)
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
		if _, err := env.roleService.SystemRolesHTTP(ctx); !errors.Is(err, test.code) {
			t.Fatalf("HTTP denial=%v want=%s", err, test.code)
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("denied directory performed %d queries", reads.Load())
	}
}

func TestRoleSystemDirectoryPreservesTenantProjectionAndCompleteNamespaces(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	roles := make([]iamentity.Role, 0, 1002)
	scopes := make([]iamentity.Scope, 0, 1002)
	for i := 0; i < 1002; i++ {
		scope := iamentity.Scope{Key: fmt.Sprintf("scope-%d", i), Name: "namespace", Type: "tenant", Path: fmt.Sprintf("/scope-%d/", i)}
		scope.ID = int64(i + 1)
		scopes = append(scopes, scope)
		roles = append(roles, iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: scope.ID,
			Name: fmt.Sprintf("system-%d", i), IsSystem: true, Status: "inactive"})
	}
	if err := env.db.CreateInBatches(&scopes, 100).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.CreateInBatches(&roles, 100).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, role := range []*iamentity.Role{
		{TenantID: "other", NamespaceScopeID: 1, Name: "other", IsSystem: true},
		{TenantID: env.tenantID, NamespaceScopeID: 1, Name: "ordinary"},
		{TenantID: env.tenantID, NamespaceScopeID: 1, Name: "deleted", IsSystem: true, DeletedAt: &now},
	} {
		if err := env.db.Create(role).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Model(&iamentity.Scope{}).Where("id = ?", 1002).UpdateColumn("deleted_at", now).Error; err != nil {
		t.Fatal(err)
	}
	rolePages, namespacePages := 0, 0
	if err := env.db.Callback().Query().After("gorm:query").Register("role:system:pages", func(tx *gorm.DB) {
		sql := tx.Statement.SQL.String()
		switch tx.Statement.Table {
		case "roles":
			rolePages++
			if !strings.Contains(sql, "tenant_id") || !strings.Contains(sql, "is_system") || !strings.Contains(sql, "deleted_at") {
				t.Errorf("directory omitted boundary: %s", sql)
			}
		case "scopes":
			namespacePages++
			if !strings.Contains(sql, " IN ") || !strings.Contains(sql, "deleted_at") {
				t.Errorf("namespace omitted relation/soft delete: %s", sql)
			}
		default:
			t.Errorf("directory hydrated undeclared table %s", tx.Statement.Table)
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx, err := scoped.WithDataScope(roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:read"), scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	result, err := env.roleService.SystemRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1002 || rolePages != 2 || namespacePages != 2 {
		t.Fatalf("roles=%d role pages=%d namespace pages=%d", len(result), rolePages, namespacePages)
	}
	seen := map[int64]bool{}
	for _, role := range result {
		if seen[role.ID] || role.Status != "inactive" || len(role.Users) != 0 || len(role.Groups) != 0 {
			t.Fatalf("duplicate or changed projection=%+v", role)
		}
		seen[role.ID] = true
		if role.NamespaceScopeID == 1002 {
			if role.NamespaceScope != nil {
				t.Fatal("deleted namespace was disclosed")
			}
		} else if role.NamespaceScope == nil || role.NamespaceScope.ID != role.NamespaceScopeID {
			t.Fatalf("missing true namespace for role %d", role.ID)
		}
	}
	// Production commands retain the providers captured during construction.
	env.roleService.roleRepo = nil
	if _, err := env.roleService.SystemRoles(ctx); err != nil {
		t.Fatalf("construction provider drifted: %v", err)
	}
}

func TestRoleSystemDirectoryPreservesSystemCoverageAndReadOnlyMissingRoot(t *testing.T) {
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
	if _, err := service.SystemRoles(ctx); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("System outside coverage=%v", err)
	}
	ctx, err = hostauthz.WithPrincipal(env.backgroundCtx, hostauthz.Principal{IsSystem: true, ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
	reads := 0
	if err := env.db.Callback().Query().After("gorm:query").Register("role:system:coverage", func(tx *gorm.DB) {
		if tx.Statement.Table == "tenants" {
			reads++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SystemRoles(ctx); err != nil || reads != 1 {
		t.Fatalf("System inside coverage=%v tenant fact reads=%d", err, reads)
	}
	if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", env.tenantID).UpdateColumn("root_scope_id", nil).Error; err != nil {
		t.Fatal(err)
	}
	writes := &atomic.Int64{}
	if err := env.db.Callback().Create().Before("gorm:create").Register("role:system:create", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("role:system:update", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SystemRoles(ctx); !errors.Is(err, errors.Internal) || writes.Load() != 0 {
		t.Fatalf("missing root error=%v provisioning writes=%d", err, writes.Load())
	}
}
