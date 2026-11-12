package router

import (
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
)

func TestRoleWritesBindActualHTTPEntries(t *testing.T) {
	routes, _ := roleRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/roles"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerRoleWriteRoutes(group); err != nil {
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
			if entry.Module != "iam" || entry.Source == "" || entry.ResourceAccess != auth.ResourceAccessData || entry.ConditionPath == "" || len(entry.Resources) != 0 {
				t.Fatalf("incomplete role write=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid role write=%+v", entry)
		}
	}
	if len(server.Routes()) != 6 || declared != 3 || allowed != 3 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound role writes passed the gate")
	}
	t.Log("Role writes HTTP actual=6 declared=3 explicit_allow=3 invalid=0")
}

func TestRoleWritesUseDeclarationsOnActualHTTP(t *testing.T) {
	routes, storage := roleRoutesFixture(t)
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 1, OwnerID: "owner", Name: "target", Status: "active", Permissions: iamentity.PermissionArray{"test:api:read"}}
	role.ID = 99
	if err := storage.Create(role).Error; err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"role:api:write", "role:api:manage"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx = tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "tenant-a"})
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path, status string }{{"POST", "/iam/roles/99/deactivate", "inactive"}, {"POST", "/iam/roles/99/activate", "active"},
		{"DELETE", "/iam/roles/99/permissions/test:api:read", "active"}} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest(test.method, test.path, nil).WithContext(ctx))
		if rec.Code != 200 {
			t.Fatalf("HTTP %s status=%d body=%s", test.path, rec.Code, rec.Body.String())
		}
		var stored iamentity.Role
		if err := storage.First(&stored, role.ID).Error; err != nil || stored.Status != test.status {
			t.Fatalf("HTTP %s stored=%+v error=%v", test.path, &stored, err)
		}
		if strings.Contains(test.path, "/permissions/") && len(stored.Permissions) != 0 {
			t.Fatalf("HTTP permission removal retained=%q", stored.Permissions)
		}
	}
}
