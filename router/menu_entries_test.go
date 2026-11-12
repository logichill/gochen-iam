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
	menusvc "gochen-iam/service/menu"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestMenuRoutesBindEveryActualHTTPEntry(t *testing.T) {
	routes, _ := menuRoutesFixture(t)
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
			if entry.Module != "iam" || entry.ResourceAccess != auth.ResourceAccessData || entry.ConditionPath == "" {
				t.Fatalf("invalid binding=%+v", entry)
			}
			if entry.Action == "http_sync" && len(entry.Resources) != 2 {
				t.Fatalf("sync lacks create/relations=%+v", entry)
			}
			if entry.Action == "http_publish" && len(entry.Resources) != 1 {
				t.Fatalf("publish lacks relations=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid entry=%+v", entry)
		}
	}
	if len(server.Routes()) != 26 || declared != 15 || allowed != 11 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	t.Logf("actual=%d declared=%d explicit_allow=%d invalid=0", len(server.Routes()), declared, allowed)
}

func TestMenuActualHTTPExecutesLifecycleThroughDeclarations(t *testing.T) {
	routes, _ := menuRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"menu:api:*"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	request := func(method, path, body string, identity context.Context, status int) []byte {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/iam/menus"+path, strings.NewReader(body)).WithContext(identity)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != status {
			t.Fatalf("%s %s: status=%d body=%s", method, path, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.Bytes()
	}
	body := request("POST", "", `{"code":"created","title":"Created","type":"page"}`, ctx, http.StatusOK)
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.ID <= 0 {
		t.Fatalf("missing ID: %s", body)
	}
	path := fmt.Sprintf("/%d", created.Data.ID)
	request("PUT", path, `{"title":"Updated","version":0}`, ctx, http.StatusOK)
	request("PUT", path, `{"title":"Stale","version":0}`, ctx, http.StatusConflict)
	published := request("POST", path+"/publish", "", ctx, http.StatusOK)
	if !strings.Contains(string(published), `"published":true`) {
		t.Fatalf("publish response=%s", published)
	}
	navigation := request("GET", "/me", "", ctx, http.StatusOK)
	if !strings.Contains(string(navigation), `"code":"created"`) {
		t.Fatalf("navigation response=%s", navigation)
	}
	request("POST", path+"/unpublish", "", ctx, http.StatusOK)
	request("DELETE", path, "", ctx, http.StatusOK)
	request("GET", path, "", ctx, http.StatusNotFound)
	restored := request("POST", path+"/restore", "", ctx, http.StatusOK)
	if !strings.Contains(string(restored), `"title":"Updated"`) {
		t.Fatalf("restore response=%s", restored)
	}
	request("POST", path+"/restore", "", ctx, http.StatusOK)
	request("DELETE", path+"/purge", "", ctx, http.StatusOK)
	request("GET", path, "", ctx, http.StatusNotFound)
	synced := request("POST", "/sync", `{"upsert":true,"items":[{"code":"child","title":"Child","parent_code":"root"},{"code":"root","title":"Root","type":"group"}]}`, ctx, http.StatusOK)
	if !strings.Contains(string(synced), `"created":["child","root"]`) {
		t.Fatalf("sync response=%s", synced)
	}
	listing := request("GET", "?page=3&size=1", "", ctx, http.StatusOK)
	if !strings.Contains(string(listing), `"code":"child"`) || !strings.Contains(string(listing), `"code":"root"`) {
		t.Fatalf("unpaged listing=%s", listing)
	}
}

func TestMenuActualHTTPFailsGateWithoutBindings(t *testing.T) {
	routes, _ := menuRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound menu routes passed startup gate")
	}
}

func TestMenuRoutesRequireCompiledService(t *testing.T) {
	for _, service := range []*menusvc.MenuService{nil, {}} {
		if _, err := NewMenuRoutes(service); err == nil {
			t.Fatal("undeclared menu service accepted")
		}
	}
}

func TestMenuActualHTTPRejectsAnonymousRequests(t *testing.T) {
	routes, _ := menuRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path, body string }{
		{"GET", "", ""}, {"GET", "/me", ""}, {"GET", "/1", ""},
		{"POST", "", `{"code":"denied","title":"Denied"}`}, {"PUT", "/1", `{"version":0,"title":"Denied"}`}, {"DELETE", "/1", ""},
		{"POST", "/sync", `{"items":[{"code":"denied","title":"Denied"}]}`}, {"POST", "/1/restore", ""}, {"DELETE", "/1/purge", ""}, {"POST", "/1/publish", ""}, {"POST", "/1/unpublish", ""},
	} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(test.method, "/iam/menus"+test.path, strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: status=%d body=%s", test.method, test.path, recorder.Code, recorder.Body.String())
		}
	}
}
