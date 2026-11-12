package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	scopesvc "gochen-iam/service/scope"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestScopeRoutesBindEveryActualHTTPEntry(t *testing.T) {
	routes, _, _ := scopeRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/api/iam"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
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
			if entry.Module != "iam" || entry.ResourceAccess != auth.ResourceAccessData || entry.Plan.Descriptor.Resource != "iam.scope.tree" || entry.ConditionPath == "" {
				t.Fatalf("invalid tree binding=%+v", entry)
			}
			if entry.Action == "http_delete" || entry.Action == "http_list" || entry.Action == "http_repair" {
				want := 5
				if entry.Action == "http_delete" {
					want = 6
				}
				if len(entry.Resources) != want {
					t.Fatalf("missing reference resources=%+v", entry)
				}
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid entry=%+v", entry)
		}
	}
	if len(server.Routes()) != 16 || declared != 10 || allowed != 6 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	t.Log("actual=16 declared=10 explicit_allow=6 invalid=0")
}

func TestScopeActualHTTPFailsGateWithoutBindings(t *testing.T) {
	routes, _, _ := scopeRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound actual scope routes passed startup gate")
	}
}

func TestScopeHTTPExecutesLifecycleAndGovernanceThroughDeclarations(t *testing.T) {
	routes, storage, scopes := scopeRoutesFixture(t)
	root := &iamentity.Scope{Key: "platform", Name: "Platform", Type: iamentity.ScopeTypePlatform, Path: "/platform/", Status: iamentity.ScopeStatusActive}
	root.ID = 100
	if err := storage.Create(root).Error; err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", Permissions: []string{"*:*:*"}, ActiveScopeID: root.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, root.ID, iamentity.ScopeTypePlatform)
	if err := scopes.RebuildVisibilityMap(ctx); err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, identity context.Context, status int) []byte {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/iam/scopes"+path, strings.NewReader(body)).WithContext(identity)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s %s: status=%d body=%s", method, path, rec.Code, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	for _, denied := range []struct{ method, path, body string }{
		{"GET", "", ""}, {"GET", "/100/visibility", ""}, {"POST", "", `{"key":"child","name":"Child","type":"region","parent_id":100}`}, {"PUT", "/100", `{"name":"Updated"}`}, {"POST", "/100/activate", ""}, {"POST", "/100/deactivate", ""}, {"POST", "/100/repair", ""}, {"DELETE", "/100", ""},
	} {
		request(denied.method, denied.path, denied.body, t.Context(), http.StatusUnauthorized)
	}
	body := request("POST", "", `{"key":"child","name":"Child","type":"region","parent_id":100}`, ctx, http.StatusOK)
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.ID <= 0 {
		t.Fatalf("missing created ID: %s", body)
	}
	path := fmt.Sprintf("/%d", created.Data.ID)
	request("PUT", path, `{"name":"Updated"}`, ctx, http.StatusOK)
	request("POST", path+"/deactivate", "", ctx, http.StatusOK)
	request("POST", path+"/activate", "", ctx, http.StatusOK)
	if err := storage.Model(&iamentity.Scope{}).Where("id = ?", created.Data.ID).Updates(map[string]any{"path": "/drift/", "depth": 9}).Error; err != nil {
		t.Fatal(err)
	}
	listing := request("GET", "", "", ctx, http.StatusOK)
	if !strings.Contains(string(listing), `"health_status":"drifted"`) || !strings.Contains(string(listing), `"can_repair":true`) {
		t.Fatalf("missing drift governance: %s", listing)
	}
	repaired := request("POST", path+"/repair", "", ctx, http.StatusOK)
	if !strings.Contains(string(repaired), `"health_status":"healthy"`) || !strings.Contains(string(repaired), `"path":"/platform/child/"`) {
		t.Fatalf("missing repaired governance: %s", repaired)
	}
	visibility := request("GET", "/100/visibility", "", ctx, http.StatusOK)
	if !strings.Contains(string(visibility), `"visible_scope_ids"`) || !strings.Contains(string(visibility), `"key":"child"`) {
		t.Fatalf("missing visibility: %s", visibility)
	}
	request("DELETE", path, "", ctx, http.StatusOK)
	var count int64
	if err := storage.Model(&iamentity.Scope{}).Where("id = ? AND deleted_at IS NULL", created.Data.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("declared delete did not persist")
	}
}

func TestScopeRoutesRejectMissingCompiledService(t *testing.T) {
	for _, service := range []*scopesvc.ScopeService{nil, {}} {
		if _, err := NewScopeRoutes(service); err == nil {
			t.Fatal("undeclared scope service accepted")
		}
	}
}
