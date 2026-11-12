package router

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gorm.io/gorm"
)

func TestRoleCRUDActualEntriesCoverGovernanceAndRejectBeforeReads(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	routes, storage := roleRoutesFixture(t)
	item := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 1, OwnerID: svc.TenantOwnerID("tenant-a"), Code: "crud-target", Name: "crud-target", Status: "active", Permissions: iamentity.PermissionArray{"role:api:read"}}
	if err := storage.Create(item).Error; err != nil {
		t.Fatal(err)
	}
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
	covered := map[string]bool{}
	for _, entry := range entries.Report() {
		if entry.Class != auth.EntryDeclared {
			continue
		}
		for _, resource := range entry.Resources {
			covered[resource.Name] = true
		}
	}
	for _, name := range []string{"names", "user_references", "group_references", "namespaces"} {
		if !covered[name] {
			t.Fatalf("actual HTTP entries omitted %s", name)
		}
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"role:api:read", "role:api:manage"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "tenant")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx = tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: "tenant-a"})
	var reads atomic.Int64
	if err := storage.Callback().Query().Before("gorm:query").Register("role-http-crud:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/iam/roles/"+strconv.FormatInt(item.ID, 10), strings.NewReader(`{"version":0,"name":"forbidden"}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 403 || reads.Load() != 0 {
		t.Fatalf("missing write permission read data: status=%d reads=%d body=%s", recorder.Code, reads.Load(), recorder.Body.String())
	}
}
