package router

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/contextx"
)

func TestPermissionProjectionEndpointsExecuteDeclaredRelations(t *testing.T) {
	routes, storage := userAssociationRoutesFixture(t)
	for i, scope := range []int64{1, 2} {
		user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: scope, ManagedScopeID: scope, OwnerID: "owner", Username: []string{"visible", "hidden"}[i], Email: []string{"visible@test", "hidden@test"}[i], Status: "active"}
		user.ID = int64(99 + i)
		if err := storage.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	// A visible user's effective credentials retain their actual role binding,
	// including a role outside the operator's separate role-directory scope.
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 2, OwnerID: "owner", Name: "credential-role", Status: "active", Permissions: iamentity.PermissionArray{"sample:api:read"}}
	role.ID = 7
	for _, item := range []any{role, &iamentity.UserRoleBinding{UserID: 99, RoleID: 7, GrantScopeID: 1, Status: "active"}} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
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
	principal := func(permissions ...string) context.Context {
		ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "1", ActiveScopeID: 1, Permissions: permissions})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
		ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
		if err != nil {
			t.Fatal(err)
		}
		return tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "tenant-a"})
	}
	if _, err := routes.userService.UserPermissions(principal("user:api:read", "user:api:manage"), 99); err != nil {
		t.Fatalf("direct declared permission query: %v", err)
	}
	for _, test := range []struct {
		ctx  context.Context
		id   string
		code int
	}{
		{t.Context(), "99", 401}, {principal("user:api:manage"), "99", 403},
		{principal("user:api:read", "user:api:manage"), "99", 200},
		{principal("user:api:read", "user:api:manage"), "100", 404},
	} {
		for _, endpoint := range []struct{ method, path, body string }{{"GET", "/permissions", ""}, {"POST", "/check-permission", `{"permission":"sample:api:read"}`}} {
			rec := httptest.NewRecorder()
			request := httptest.NewRequest(endpoint.method, "/iam/users/"+test.id+endpoint.path, strings.NewReader(endpoint.body)).WithContext(test.ctx)
			request.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(rec, request)
			if rec.Code != test.code {
				t.Fatalf("%s status=%d want=%d body=%s", endpoint.path, rec.Code, test.code, rec.Body.String())
			}
			if test.code == 200 {
				if endpoint.method == "GET" && !strings.Contains(rec.Body.String(), `"sample:api:read"`) {
					t.Fatalf("lost bound role credential: %s", rec.Body.String())
				}
				if endpoint.method == "POST" && !strings.Contains(rec.Body.String(), `"allowed":true`) {
					t.Fatalf("permission check differs from projection: %s", rec.Body.String())
				}
			}
		}
	}
}
