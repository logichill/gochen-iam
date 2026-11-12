package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestTenantCustomActionsBindActualHTTPResources(t *testing.T) {
	routes, _ := tenantRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"POST /iam/tenants/{id}/activate":          "http_activate",
		"POST /iam/tenants/{id}/deactivate":        "http_deactivate",
		"POST /iam/tenants/{id}/repair-root-scope": "http_repair",
	}
	for _, status := range registry.Report() {
		action, exists := want[status.Entry.Key]
		if !exists {
			continue
		}
		if status.Class != auth.EntryDeclared || status.Module != "iam" || status.Action != action || status.Plan == nil || status.Plan.Descriptor.Resource != svc.TenantResourceKind || status.ConditionPath == "" {
			t.Fatalf("invalid custom action binding=%+v", status)
		}
		count := 0
		if action == "http_repair" {
			count = 3
		}
		if len(status.Resources) != count {
			t.Fatalf("custom action missing resources=%+v", status)
		}
		delete(want, status.Entry.Key)
	}
	if len(want) != 0 {
		t.Fatalf("missing custom entries=%v", want)
	}
	// The complete standard/custom set is verified by TestTenantCompleteActualHTTPBindings.
}

func TestTenantCustomActionsUseDeclarationsOnRealHTTP(t *testing.T) {
	routes, storage := tenantRoutesFixture(t)
	tenant := &iamentity.Tenant{Key: "tenant-http", Name: "HTTP Tenant", Status: svc.TenantStatusInactive}
	tenant.ID = 42
	if err := storage.Create(tenant).Error; err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	principal := func(permissions []string, system bool, kind string) context.Context {
		t.Helper()
		ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: permissions, IsSystem: system})
		if err != nil {
			t.Fatal(err)
		}
		return iamauth.BindActiveScopeContext(ctx, 1, kind)
	}
	request := func(action string, ctx context.Context, status int) string {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/iam/tenants/42/"+action, nil).WithContext(ctx)
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s status=%d body=%s", action, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	for _, action := range []string{"activate", "deactivate", "repair-root-scope"} {
		request(action, t.Context(), http.StatusUnauthorized)
		request(action, principal([]string{"tenant:api:read"}, false, "platform"), http.StatusForbidden)
		request(action, principal([]string{"tenant:api:*"}, true, "tenant"), http.StatusForbidden)
	}
	var unchanged iamentity.Tenant
	if err := storage.First(&unchanged, 42).Error; err != nil {
		t.Fatal(err)
	}
	if unchanged.Version != tenant.Version || unchanged.Status != tenant.Status || unchanged.RootScopeID != nil {
		t.Fatal("denied HTTP changed tenant")
	}
	activation := principal([]string{"tenant:api:activate"}, false, "platform")
	for _, action := range []string{"activate", "deactivate"} {
		body := request(action, activation, http.StatusOK)
		status := svc.TenantStatusActive
		if action == "deactivate" {
			status = svc.TenantStatusInactive
		}
		if !strings.Contains(body, fmt.Sprintf(`"status":"%s"`, status)) {
			t.Fatalf("transition response=%s", body)
		}
		var saved iamentity.Tenant
		if err := storage.First(&saved, 42).Error; err != nil {
			t.Fatal(err)
		}
		if saved.Status != status {
			t.Fatalf("transition not persisted=%+v", saved)
		}
	}
	write := principal([]string{"tenant:api:write"}, false, "platform")
	body := request("repair-root-scope", write, http.StatusOK)
	if !strings.Contains(body, `"root_scope_key":"tenant:tenant-http"`) {
		t.Fatalf("root response=%s", body)
	}
	var repaired iamentity.Tenant
	if err := storage.First(&repaired, 42).Error; err != nil {
		t.Fatal(err)
	}
	if repaired.RootScopeID == nil {
		t.Fatal("HTTP repair did not persist tenant link")
	}
	single := iamtenant.WithPolicy(principal([]string{"tenant:api:activate"}, true, "tenant"), iamtenant.Policy{Mode: iamtenant.ModeSingle})
	request("activate", single, http.StatusOK)
}

func TestTenantRoutesRejectUndeclaredServiceBeforeRegistration(t *testing.T) {
	for _, service := range []*tenantsvc.TenantService{nil, {}} {
		routes, _ := tenantRoutesFixture(t)
		if service == nil {
			routes.tenantService = nil
		} else {
			routes.tenantService = service
		}
		root := newRecordingGroup("", nil)
		if err := routes.RegisterRoutes(root); err == nil {
			t.Fatal("undeclared service registered")
		}
		if len(root.routes) != 0 {
			t.Fatal("invalid service partially registered tenant routes")
		}
	}
}
