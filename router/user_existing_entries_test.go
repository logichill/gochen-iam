package router

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"golang.org/x/crypto/bcrypt"
)

func TestUserExistingCRUDActualRESTBindingsAndTransactions(t *testing.T) {
	routes, storage := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerCRUDRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range entries.Report() {
		if entry.Class == auth.EntryDeclared {
			counts[entry.Action]++
			if (entry.Action == "update" || entry.Action == "delete") && (len(entry.Resources) != 0 || entry.ConditionPath == "") {
				t.Fatalf("write lacks actual primary command plan=%+v", entry)
			}
			if entry.Action == "update" {
				if _, ok := entry.Plan.Descriptor.Action("read"); !ok {
					t.Fatalf("PUT initial read absent=%+v", entry)
				}
			}
		}
	}
	if counts["read"] != 2 || counts["update"] != 2 || counts["delete"] != 2 {
		t.Fatalf("existing CRUD bindings=%v", counts)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"primary", "second", "hidden"} {
		scope := int64(1)
		if name == "hidden" {
			scope = 2
		}
		user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: scope, ManagedScopeID: scope, OwnerID: "owner", Username: name, Email: name + "@example.test", Password: string(hash), Status: "active"}
		user.ID = int64(i + 100)
		if err := storage.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:read", "user:api:write", "user:api:delete", "user:api:manage"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, status int) string {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/iam/users"+path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s %s status=%d body=%s", method, path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	load := func(id int64) *iamentity.User {
		t.Helper()
		var user iamentity.User
		if err := storage.First(&user, id).Error; err != nil {
			t.Fatal(err)
		}
		return &user
	}
	request("GET", "/100", "", 200)
	request("PUT", "/100", `{"version":0,"avatar":"one"}`, 200)
	if user := load(100); user.Version != 1 || user.Avatar != "one" || user.Password != string(hash) {
		t.Fatalf("update changed unexpected fields=%+v", user)
	}
	request("PUT", "/100", `{"version":1,"avatar":"one","password":""}`, 200)
	if user := load(100); user.Version != 1 || user.Password != string(hash) {
		t.Fatal("empty password/no-op update did not preserve the existing hash/version")
	}
	body := request("PUT", "/100", `{"version":1,"password":"new-password"}`, 200)
	if strings.Contains(body, "new-password") || strings.Contains(body, "$2") {
		t.Fatal("password appeared in the response")
	}
	updated := load(100)
	if updated.Version != 2 || bcrypt.CompareHashAndPassword([]byte(updated.Password), []byte("new-password")) != nil {
		t.Fatal("new password was not persisted as bcrypt")
	}
	request("PUT", "/100", `{"version":2,"password":"short"}`, 400)
	request("PUT", "/100", `{"version":2,"password":"`+strings.Repeat("x", 73)+`"}`, 400)
	request("PUT", "/100", `{"version":1,"avatar":"stale"}`, 409)
	request("PUT", "/100", `{"version":2,"managed_scope_id":2}`, 403)
	request("PUT", "/bulk", `[{"id":100,"version":2,"username":"primary","email":"primary@example.test","avatar":"rollback"},{"id":101,"version":1,"username":"second","email":"second@example.test"}]`, 409)
	if user := load(100); user.Version != 2 || user.Avatar != "one" {
		t.Fatalf("stale second bulk update did not roll back first=%+v", user)
	}
	request("PUT", "/bulk", `[{"id":100,"version":2,"username":"primary","email":"primary@example.test","avatar":"bulk"},{"id":101,"version":0,"username":"second","email":"second@example.test","avatar":"bulk"}]`, 200)
	if user := load(100); user.Version != 3 || user.Avatar != "bulk" || user.HomeScopeID != 1 || user.HomeTenantID != "tenant-a" {
		t.Fatalf("bulk update did not preserve normalization=%+v", user)
	}
	request("DELETE", "/bulk", `{"ids":[100,102]}`, 404)
	if user := load(100); user.DeletedAt != nil || user.Version != 3 {
		t.Fatalf("scope-rejected bulk deletion did not roll back first=%+v", user)
	}
	request("DELETE", "/101", "", 200)
	if user := load(101); user.DeletedAt == nil {
		t.Fatal("single delete did not retain the user as a soft-deleted record")
	}
	request("DELETE", "/bulk", `{"ids":[100]}`, 200)
	if user := load(100); user.DeletedAt == nil {
		t.Fatal("bulk delete did not soft delete the user")
	}
	request("GET", "/100", "", 404)
	t.Log("User read/update/delete actual REST declarations, password/version behavior and bulk rollback verified")
}

func TestUserExistingCRUDPreservesHTTPDenials(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	base, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		subject, kind string
		permissions   []string
		status        int
	}{{"", "platform", nil, 401}, {"opaque", "platform", []string{"*:*:*"}, 401}, {"7", "department", []string{"*:*:*"}, 403}, {"7", "platform", []string{"user:api:manage"}, 403}, {"7", "platform", []string{"user:api:write", "user:api:delete"}, 403}} {
		ctx := context.Context(base)
		if test.subject != "" {
			ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: test.subject, ActiveScopeID: 1, Permissions: test.permissions})
			if err != nil {
				t.Fatal(err)
			}
			ctx = iamauth.BindActiveScopeContext(ctx, 1, test.kind)
		}
		for _, request := range []struct{ method, path, body string }{{"GET", "/100", ""}, {"PUT", "/100", `{"version":0,"avatar":"denied"}`}, {"PUT", "/bulk", `[{"id":100,"version":0}]`}, {"DELETE", "/100", ""}, {"DELETE", "/bulk", `{"ids":[100]}`}} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(request.method, "/iam/users"+request.path, strings.NewReader(request.body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != test.status {
				t.Fatalf("%s/%s %s %s status=%d body=%s", test.subject, test.kind, request.method, request.path, rec.Code, rec.Body.String())
			}
		}
	}
}
