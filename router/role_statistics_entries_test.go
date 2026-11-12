package router

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/contextx"
	"gochen/testkit"
	"gorm.io/gorm"
)

func roleRoutesFixture(t *testing.T) (*RoleRoutes, *gorm.DB) {
	t.Helper()
	_, storage, scopes := scopeRoutesFixture(t)
	groups, err := grouprepo.NewGroupRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := svc.NewIAMAccess(nil)
	service, err := rolesvc.NewRoleService(roles, users, groups, nil, authorizer, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewRoleRoutes(service, roles, nil, authorizer), storage
}

func TestRoleStatisticsBindsActualHTTPEntries(t *testing.T) {
	routes, _ := roleRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/roles"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerRoleStatisticsRoute(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
			if entry.Action != "http_statistics" || entry.Source == "" || entry.ConditionPath == "" || len(entry.Resources) != 0 {
				t.Fatalf("incomplete role statistics binding=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid role statistics entry=%+v", entry)
		}
	}
	if len(server.Routes()) != 3 || declared != 2 || allowed != 1 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound statistics passed the startup gate")
	}
	t.Log("Role statistics HTTP actual=3 declared=2 explicit_allow=1 invalid=0")
}

func TestRoleCompleteRootValidatesEveryCustomEntry(t *testing.T) {
	routes, _ := roleRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed, invalid := 0, 0, 0
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
		case auth.EntryAllowed:
			allowed++
		default:
			invalid++
		}
	}
	if invalid != 0 || declared == 0 {
		t.Fatal("Role complete root has invalid or missing declared entries")
	}
	t.Logf("Role complete HTTP root actual=%d declared=%d allowed=%d invalid=%d; complete Role root verified", len(server.Routes()), declared, allowed, invalid)
}

func TestRoleStatisticsActualHTTPPreservesPayloadAndAuthorization(t *testing.T) {
	routes, storage := roleRoutesFixture(t)
	for i, scopeID := range []int64{1, 2} {
		role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: scopeID, Name: []string{"visible", "hidden"}[i], Status: "active", IsSystem: true}
		if err := storage.Create(role).Error; err != nil {
			t.Fatal(err)
		}
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.registerRoleStatisticsRoute(server.Group("/iam/roles")); err != nil {
		t.Fatal(err)
	}
	principal := func(subject, kind string, permissions ...string) context.Context {
		t.Helper()
		ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: subject, ActiveScopeID: 1, Permissions: permissions})
		if err != nil {
			t.Fatal(err)
		}
		return iamauth.BindActiveScopeContext(ctx, 1, kind)
	}
	for _, test := range []struct {
		ctx    context.Context
		status int
	}{
		{t.Context(), 401},
		{principal("7", "tenant", "role:api:read"), 403},
		{principal("trace", "tenant", "role:api:read", "role:api:manage"), 401},
		{principal("7", "department", "role:api:read", "role:api:manage"), 403},
		{principal("7", "tenant", "role:api:read", "role:api:manage"), 200},
	} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/iam/roles/statistics", nil).WithContext(test.ctx))
		if rec.Code != test.status {
			t.Fatalf("HTTP status=%d want=%d body=%s", rec.Code, test.status, rec.Body.String())
		}
		if rec.Code == 200 {
			var result struct {
				Data struct {
					Total  int64            `json:"total_roles"`
					Active int              `json:"active_roles"`
					System int              `json:"system_roles"`
					Status map[string]int64 `json:"roles_by_status"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Data.Total != 1 || result.Data.Active != 1 || result.Data.System != 1 || result.Data.Status["active"] != 1 {
				t.Fatalf("statistics payload=%s error=%v", rec.Body.String(), err)
			}
		}
	}
}
