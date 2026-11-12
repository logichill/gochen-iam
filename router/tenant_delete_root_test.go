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
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gorm.io/gorm"
)

func tenantDeleteRootFixture(t *testing.T) (*TenantRoutes, *gorm.DB, context.Context) {
	t.Helper()
	routes, storage := tenantRoutesFixture(t)
	platform := &iamentity.Scope{Key: "platform", Name: "Platform", Type: iamentity.ScopeTypePlatform, Path: "/platform/", Status: iamentity.ScopeStatusActive}
	platform.SetID(1)
	if err := storage.Create(platform).Error; err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"a", "b"} {
		root := &iamentity.Scope{Key: "tenant:" + key, Name: key, Type: iamentity.ScopeTypeTenant, ParentID: &platform.ID,
			Path: iamentity.ScopePathFor(platform.Path, "tenant:"+key), Depth: 1, Status: iamentity.ScopeStatusActive}
		root.SetID(int64(10 + i))
		if err := storage.Create(root).Error; err != nil {
			t.Fatal(err)
		}
		tenant := &iamentity.Tenant{Key: key, Name: key, Status: svc.TenantStatusInactive, RootScopeID: &root.ID}
		tenant.SetID(int64(100 + i))
		if err := storage.Create(tenant).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := routes.scopeRepo.RebuildVisibilityMap(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(t.Context(), hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"tenant:api:read", "tenant:api:delete"}})
	if err != nil {
		t.Fatal(err)
	}
	return routes, storage, iamauth.BindActiveScopeContext(ctx, 1, iamentity.ScopeTypePlatform)
}

func tenantDeleteRootRequest(t *testing.T, routes *TenantRoutes, ctx context.Context, path, body string, want int) string {
	t.Helper()
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/iam/tenants"+path, strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("DELETE %s status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func assertTenantRootsIntact(t *testing.T, storage *gorm.DB) {
	t.Helper()
	for _, id := range []int64{100, 101} {
		var tenant iamentity.Tenant
		if err := storage.First(&tenant, id).Error; err != nil || tenant.DeletedAt != nil || tenant.Version != 0 {
			t.Fatalf("tenant partially deleted: %+v error=%v", tenant, err)
		}
	}
	for _, id := range []int64{1, 10, 11} {
		var root iamentity.Scope
		if err := storage.First(&root, id).Error; err != nil || root.DeletedAt != nil || root.Version != 0 {
			t.Fatalf("root partially deleted: %+v error=%v", root, err)
		}
	}
}

func TestTenantDeleteRejectsDriftOnActualHTTPAndKeepsOtherRoots(t *testing.T) {
	for _, test := range []struct {
		name       string
		change     map[string]any
		rootChange map[string]any
	}{
		{name: "other tenant reference", change: map[string]any{"root_scope_id": 11}},
		{name: "platform reference", change: map[string]any{"root_scope_id": 1}},
		{name: "missing reference", change: map[string]any{"root_scope_id": 99}},
		{name: "key drift", rootChange: map[string]any{"key": "tenant:other"}},
		{name: "type drift", rootChange: map[string]any{"type": "org"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			routes, storage, ctx := tenantDeleteRootFixture(t)
			if test.change != nil {
				if err := storage.Model(&iamentity.Tenant{}).Where("id = ?", 100).Updates(test.change).Error; err != nil {
					t.Fatal(err)
				}
			} else if err := storage.Model(&iamentity.Scope{}).Where("id = ?", 10).Updates(test.rootChange).Error; err != nil {
				t.Fatal(err)
			}
			body := tenantDeleteRootRequest(t, routes, ctx, "/100", "", http.StatusBadRequest)
			if !strings.Contains(body, "先修复") {
				t.Fatalf("missing repair hint=%s", body)
			}
			assertTenantRootsIntact(t, storage)
		})
	}
}

func TestTenantDeleteActualHTTPBulkRollsBackRootAndVisibility(t *testing.T) {
	for _, mode := range []string{"second target drift", "tenant save failure", "visibility rebuild failure"} {
		t.Run(mode, func(t *testing.T) {
			routes, storage, ctx := tenantDeleteRootFixture(t)
			var before int64
			if err := storage.Model(&iamentity.ScopeVisibility{}).Count(&before).Error; err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "second target drift":
				if err := storage.Model(&iamentity.Tenant{}).Where("id = ?", 101).Update("root_scope_id", 10).Error; err != nil {
					t.Fatal(err)
				}
			case "tenant save failure":
				if err := storage.Exec(`CREATE TRIGGER reject_tenant_delete BEFORE UPDATE ON tenants WHEN NEW.id=101 AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected tenant delete failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			case "visibility rebuild failure":
				if err := storage.Exec(`CREATE TRIGGER reject_visibility_rebuild BEFORE DELETE ON scope_visibility_map BEGIN SELECT RAISE(ABORT, 'injected visibility failure'); END`).Error; err != nil {
					t.Fatal(err)
				}
			}
			want := http.StatusInternalServerError
			if mode == "second target drift" {
				want = http.StatusBadRequest
			}
			tenantDeleteRootRequest(t, routes, ctx, "/bulk", `{"ids":[100,101]}`, want)
			assertTenantRootsIntact(t, storage)
			var after int64
			if err := storage.Model(&iamentity.ScopeVisibility{}).Count(&after).Error; err != nil || after != before {
				t.Fatalf("visibility rollback before=%d after=%d error=%v", before, after, err)
			}
		})
	}
}

func TestTenantDeleteActualHTTPDeletesOnlyMatchingRoot(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprintf("bulk=%t", bulk), func(t *testing.T) {
			routes, storage, ctx := tenantDeleteRootFixture(t)
			path, body := "/100", ""
			if bulk {
				path, body = "/bulk", `{"ids":[100,101]}`
			}
			tenantDeleteRootRequest(t, routes, ctx, path, body, http.StatusOK)
			for _, id := range []int64{100, 101} {
				var tenant iamentity.Tenant
				if err := storage.First(&tenant, id).Error; err != nil {
					t.Fatal(err)
				}
				deleted := id == 100 || bulk
				if (tenant.DeletedAt != nil) != deleted {
					t.Fatalf("tenant deletion=%+v", tenant)
				}
				var root iamentity.Scope
				if err := storage.First(&root, id-90).Error; err != nil {
					t.Fatal(err)
				}
				if (root.DeletedAt != nil) != deleted {
					t.Fatalf("root deletion=%+v", root)
				}
			}
			var platform iamentity.Scope
			if err := storage.First(&platform, 1).Error; err != nil || platform.DeletedAt != nil {
				t.Fatalf("platform changed=%+v error=%v", platform, err)
			}
		})
	}
}
