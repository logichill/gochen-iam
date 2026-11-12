package router

import (
	"encoding/json"
	"net/http"
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

func TestUserCreateActualHTTPUsesFixedServiceAndRejectsAssociations(t *testing.T) {
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
	declared, allowed, create := 0, 0, 0
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
			if entry.Action == "create" {
				create++
				if entry.Plan == nil || entry.Plan.Descriptor.Resource != "user" || entry.ConditionPath == "" || len(entry.Resources) != 0 {
					t.Fatalf("create binding=%+v", entry)
				}
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid CRUD entry=%+v", entry)
		}
	}
	if declared != 10 || allowed != 3 || create != 2 {
		t.Fatalf("CRUD entries declared=%d allowed=%d create=%d report=%+v", declared, allowed, create, entries.Report())
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:manage", "user:api:read", "user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, body string, want int) string {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/iam/users"+path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("POST %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	base := `{"username":"created","email":"created@example.test","password":"secret-password","home_tenant_id":"forged","home_scope_id":99}`
	for _, relation := range []string{`"groups":[{"id":77}]`, `"roles":[{"id":88}]`} {
		body := request("", strings.TrimSuffix(base, "}")+","+relation+"}", http.StatusBadRequest)
		if !strings.Contains(body, "分配入口") {
			t.Fatalf("missing association hint=%s", body)
		}
		request("/bulk", "["+base+","+strings.TrimSuffix(base, "}")+","+relation+"}]", http.StatusBadRequest)
		var count int64
		if err := storage.Model(&iamentity.User{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("association failure partially created users=%d error=%v", count, err)
		}
	}
	for _, table := range []string{"groups", "roles", "user_groups", "user_role_bindings"} {
		var count int64
		if err := storage.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("association write reached %s count=%d error=%v", table, count, err)
		}
	}
	body := request("", base, http.StatusOK)
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.Data.ID <= 0 {
		t.Fatalf("created response=%s error=%v", body, err)
	}
	var saved iamentity.User
	if err := storage.First(&saved, created.Data.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.TenantID != "tenant-a" || saved.HomeTenantID != "tenant-a" || saved.ManagedScopeID != 1 || saved.HomeScopeID != 1 || saved.OwnerID != "tenant:tenant-a" {
		t.Fatalf("trusted create fields=%+v", &saved)
	}
	if saved.Password == "secret-password" || bcrypt.CompareHashAndPassword([]byte(saved.Password), []byte("secret-password")) != nil || strings.Contains(body, "secret-password") || strings.Contains(body, "$2") {
		t.Fatal("create password persistence or response protection failed")
	}
	request("/bulk", `[{"username":"batch-one","email":"one@example.test","password":"secret-one"},{"username":"batch-two","email":"two@example.test","password":"secret-two"}]`, http.StatusOK)
	request("/bulk", `[{"username":"rollback-one","email":"rollback-one@example.test","password":"secret-one"},{"username":"rollback-two","email":"rollback-two@example.test","password":"short"}]`, http.StatusBadRequest)
	var count int64
	if err := storage.Model(&iamentity.User{}).Count(&count).Error; err != nil || count != 3 {
		t.Fatalf("invalid second password failed to roll back count=%d error=%v", count, err)
	}
}
