package router

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/contextx"
)

func TestRoleSystemDirectoryBindsActualHTTPEntries(t *testing.T) {
	routes, storage := roleRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/roles"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerSystemRolesRoute(group); err != nil {
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
			if entry.Action != "http_system_roles" || entry.Source == "" || entry.ConditionPath == "" || len(entry.Resources) != 1 || entry.Resources[0].Name != "namespaces" {
				t.Fatalf("incomplete directory binding=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid directory entry=%+v", entry)
		}
	}
	if len(server.Routes()) != 3 || declared != 2 || allowed != 1 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound directory passed the startup gate")
	}
	scope := &iamentity.Scope{Key: "root", Name: "root", Type: "tenant", Path: "/root/"}
	scope.ID = 2
	if err := storage.Create(scope).Error; err != nil {
		t.Fatal(err)
	}
	for _, role := range []*iamentity.Role{
		{TenantID: "tenant-a", NamespaceScopeID: 2, Name: "system", IsSystem: true, Status: "inactive"},
		{TenantID: "tenant-a", NamespaceScopeID: 2, Name: "ordinary"},
		{TenantID: "tenant-b", NamespaceScopeID: 2, Name: "other", IsSystem: true},
	} {
		if err := storage.Create(role).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		subject     string
		permissions []string
		status      int
	}{
		{"7", []string{"role:api:read"}, 403},
		{"trace", []string{"role:api:read", "role:api:manage"}, 401},
		{"7", []string{"role:api:read", "role:api:manage"}, 200},
	} {
		ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: test.subject, ActiveScopeID: 1, Permissions: test.permissions})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/iam/roles/system", nil).WithContext(ctx))
		if rec.Code != test.status {
			t.Fatalf("status=%d want=%d body=%s", rec.Code, test.status, rec.Body.String())
		}
		if rec.Code == 200 {
			var result struct {
				Data []*iamentity.Role `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Data) != 1 || result.Data[0].NamespaceScope == nil || result.Data[0].NamespaceScope.ID != 2 || result.Data[0].Status != "inactive" {
				t.Fatalf("payload=%s", rec.Body.String())
			}
		}
	}
	t.Log("Role system directory HTTP actual=3 declared=2 explicit_allow=1 invalid=0")
}
