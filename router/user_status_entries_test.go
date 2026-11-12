package router

import (
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
)

func TestUserStatusBindsAllActualHTTPEntries(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerStatusRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, status := range registry.Report() {
		switch status.Class {
		case auth.EntryDeclared:
			declared++
			if status.Module != "iam" || status.ResourceAccess != auth.ResourceAccessData || status.ConditionPath == "" || len(status.Resources) != 0 {
				t.Fatalf("invalid status plan=%+v", status)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid actual status entry=%+v", status)
		}
	}
	if declared != 4 || allowed != 4 || len(server.Routes()) != 8 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	t.Log("user status actual=8 declared=4 explicit_allow=4 invalid=0")
}

func TestUserStatusCommandsOnActualHTTP(t *testing.T) {
	routes, storage := userAssociationRoutesFixture(t)
	user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	if err := storage.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:manage", "user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ action, status string }{{"lock", "locked"}, {"unlock", "active"}, {"deactivate", "inactive"}, {"activate", "active"}} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest("POST", "/iam/users/99/"+test.action, nil).WithContext(ctx))
		if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"status":"`+test.status+`"`) {
			t.Fatalf("%s status=%d body=%s", test.action, recorder.Code, recorder.Body.String())
		}
		var stored iamentity.User
		if err := storage.First(&stored, user.ID).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Status != test.status {
			t.Fatalf("%s did not persist status=%s", test.action, stored.Status)
		}
	}
}
