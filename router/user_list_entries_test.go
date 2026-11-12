package router

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
)

func TestUserListActualRESTBindingAndFiltering(t *testing.T) {
	routes, storage := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerCRUDRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	listEntries := 0
	for _, entry := range registry.Report() {
		if entry.Action == "list" {
			listEntries++
			if entry.Class != auth.EntryDeclared || entry.ResourceAccess != auth.ResourceAccessData || len(entry.Resources) != 2 || entry.ConditionPath == "" || entry.Resources[0].Name != "groups" || entry.Resources[1].Name != "roles" {
				t.Fatalf("incomplete list binding=%+v", entry)
			}
		}
	}
	if listEntries != 2 {
		t.Fatalf("GET/HEAD list entries=%d", listEntries)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("missing bindings passed the actual REST gate")
	}
	now := time.Now()
	for i, item := range []struct {
		tenant  string
		scope   int64
		name    string
		deleted *time.Time
	}{{"tenant-a", 2, "outside", nil}, {"tenant-a", 1, "visible", nil}, {"other", 1, "other", nil}, {"tenant-a", 1, "deleted", &now}} {
		user := &iamentity.User{TenantID: item.tenant, HomeTenantID: item.tenant, HomeScopeID: item.scope, ManagedScopeID: item.scope, OwnerID: "owner", Username: item.name, Email: item.name + "@example.test", Password: "hidden-secret", DeletedAt: item.deleted}
		user.ID = int64(98 + i)
		if err := storage.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"visible-association", "hidden-association"} {
		id, scope := int64(200+i), int64(i+1)
		group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: scope, OwnerID: "owner", Name: name}
		group.ID = id
		role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: scope, OwnerID: "owner", Name: name}
		role.ID = id
		for _, entity := range []any{group, role, &iamentity.UserRoleBinding{UserID: 99, RoleID: id, GrantScopeID: 1, Status: "inactive"}} {
			if err := storage.Create(entity).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", 99, id).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:read", "user:api:manage"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/iam/users?size=1", "/iam/users?size=1&sort=id:asc"} {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil).WithContext(ctx))
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, `"username":"visible"`) || !strings.Contains(body, `"total":1`) || strings.Count(body, `"name":"visible-association"`) != 2 {
			t.Fatalf("list failed conditions/pagination/associations status=%d body=%s", rec.Code, body)
		}
		for _, forbidden := range []string{"hidden-association", "hidden-secret", `"username":"outside"`, `"username":"other"`, `"username":"deleted"`} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("list disclosed %s: %s", forbidden, body)
			}
		}
	}
	t.Log("User standard list: actual GET/HEAD declarations include User/Group/Role; original inactive-binding projection preserved")
}
