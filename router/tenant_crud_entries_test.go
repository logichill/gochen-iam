package router

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func tenantCRUDPrincipal(t *testing.T) context.Context {
	t.Helper()
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"tenant:api:read", "tenant:api:write", "tenant:api:delete"}})
	if err != nil {
		t.Fatal(err)
	}
	return iamauth.BindActiveScopeContext(ctx, 1, iamentity.ScopeTypePlatform)
}
func tenantCRUDRequest(t *testing.T, server *nethttp.Server, ctx context.Context, method, path, body string, want int) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/iam/tenants"+path, strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s status=%d body=%s", method, path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestTenantCompleteActualHTTPBindings(t *testing.T) {
	routes, _ := tenantRoutesFixture(t)
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
	declared, allowed := 0, 0
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
			if entry.Plan == nil || entry.Source == "" || entry.ConditionPath == "" {
				t.Fatalf("missing actual binding=%+v", entry)
			}
			names := map[string]bool{}
			for _, resource := range entry.Resources {
				names[resource.Name] = true
				if resource.Source == "" || resource.ConditionPath == "" {
					t.Fatalf("missing resource binding=%+v", resource)
				}
			}
			switch entry.Action {
			case "create":
				if len(names) != 3 || !names["root"] || !names["visibility"] || !names["link"] {
					t.Fatalf("create resources=%+v", entry)
				}
			case "read", "list", "delete":
				if len(names) != 5 || !names["users"] || !names["groups"] || !names["roles"] || !names["root"] || !names["visibility"] {
					t.Fatalf("governance resources=%+v", entry)
				}
			case "update":
				if len(names) != 6 || !names["snapshot"] {
					t.Fatalf("update resources=%+v", entry)
				}
			case "http_activate", "http_deactivate":
				if len(names) != 0 {
					t.Fatalf("transition resources=%+v", entry)
				}
			case "http_repair":
				if len(names) != 3 {
					t.Fatalf("repair resources=%+v", entry)
				}
			default:
				t.Fatalf("unexpected Tenant action=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid Tenant entry=%+v", entry)
		}
	}
	if len(server.Routes()) != 19 || declared != 13 || allowed != 6 {
		t.Fatalf("complete Tenant actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	t.Logf("complete Tenant HTTP actual=%d declared=%d explicit_allow=%d invalid=0", len(server.Routes()), declared, allowed)
}

func TestTenantCRUDActualHTTPCreateUpdateAndBulkTransactions(t *testing.T) {
	routes, storage := tenantRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	ctx := tenantCRUDPrincipal(t)
	body := tenantCRUDRequest(t, server, ctx, "POST", "", `{"key":"first","name":"First","root_scope_id":999}`, 200)
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID <= 0 {
		t.Fatalf("create result=%s error=%v", body, err)
	}
	var first iamentity.Tenant
	if err := storage.First(&first, created.ID).Error; err != nil {
		t.Fatal(err)
	}
	if first.RootScopeID == nil || *first.RootScopeID == 999 || first.Version != 1 {
		t.Fatalf("untrusted create reference/version=%+v", first)
	}
	var root iamentity.Scope
	if err := storage.First(&root, *first.RootScopeID).Error; err != nil {
		t.Fatal(err)
	}
	if root.Key != "tenant:first" || root.Type != iamentity.ScopeTypeTenant {
		t.Fatalf("created root=%+v", root)
	}
	tenantCRUDRequest(t, server, ctx, "POST", "/bulk", `[{"key":"duplicate","name":"one"},{"key":"duplicate","name":"two"}]`, 409)
	var count int64
	if err := storage.Model(&iamentity.Tenant{}).Where("key = ?", "duplicate").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("bulk create partially committed count=%d error=%v", count, err)
	}
	if err := storage.Model(&iamentity.Scope{}).Where("key = ?", "tenant:duplicate").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("bulk root create partially committed count=%d error=%v", count, err)
	}
	tenantCRUDRequest(t, server, ctx, "POST", "/bulk", `[{"key":"second","name":"Second"},{"key":"third","name":"Third"}]`, 200)
	var second, third iamentity.Tenant
	if err := storage.Where("key = ?", "second").First(&second).Error; err != nil {
		t.Fatal(err)
	}
	if err := storage.Where("key = ?", "third").First(&third).Error; err != nil {
		t.Fatal(err)
	}
	patch := func(tenant iamentity.Tenant, name string) map[string]any {
		return map[string]any{"id": tenant.ID, "key": tenant.Key, "name": name, "status": tenant.Status, "version": tenant.Version, "root_scope_id": 999}
	}
	updates, err := json.Marshal([]any{patch(second, "Updated"), patch(third, "Updated")})
	if err != nil {
		t.Fatal(err)
	}
	tenantCRUDRequest(t, server, ctx, "PUT", "/bulk", string(updates), 200)
	var updated iamentity.Tenant
	if err := storage.First(&updated, second.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || !sameTenantRootID(updated.RootScopeID, second.RootScopeID) || updated.Version != second.Version+1 {
		t.Fatalf("bulk update did not preserve trusted root=%+v", updated)
	}
	updates, err = json.Marshal([]any{patch(updated, "Rollback"), patch(third, "Stale")})
	if err != nil {
		t.Fatal(err)
	}
	tenantCRUDRequest(t, server, ctx, "PUT", "/bulk", string(updates), 409)
	var unchanged iamentity.Tenant
	if err := storage.First(&unchanged, second.ID).Error; err != nil || unchanged.Name != updated.Name || unchanged.Version != updated.Version {
		t.Fatalf("stale bulk partially committed=%+v error=%v", unchanged, err)
	}
	tenantCRUDRequest(t, server, ctx, "GET", "", "", 200)
}

func TestTenantCRUDGovernanceCountsHomeTenantAndSoftDeletes(t *testing.T) {
	routes, storage, ctx := tenantDeleteRootFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "b", HomeTenantID: "a", ManagedScopeID: 77, HomeScopeID: 10, OwnerID: "owner", Username: "home-owner", Email: "home@example.test", Status: "active", Password: "hash"}
	user.ID = 700
	if err := storage.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	body := tenantCRUDRequest(t, server, ctx, "GET", "/100", "", 200)
	if !strings.Contains(body, `"can_delete":false`) || !strings.Contains(body, "1 个用户") || !strings.Contains(body, `"root_scope_status":"healthy"`) {
		t.Fatalf("governance projection=%s", body)
	}
	tenantCRUDRequest(t, server, ctx, "DELETE", "/100", "", 400)
	if err := storage.Model(user).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	body = tenantCRUDRequest(t, server, ctx, "GET", "/100", "", 200)
	if !strings.Contains(body, `"can_delete":true`) {
		t.Fatalf("soft deleted user still occupies tenant=%s", body)
	}
	// The wrapper is a pure conversion of an already authorized projection.
	model := &tenantHTTPModel{Tenant: iamentity.Tenant{Key: "forged"}, view: svc.TenantListItem{ID: 100, Key: "a", CanDelete: true}}
	view := routes.wrapTenantResponse(model).(svc.TenantListItem)
	if view.Key != "a" || !view.CanDelete {
		t.Fatalf("wrapper recomputed trusted projection=%+v", view)
	}
}
