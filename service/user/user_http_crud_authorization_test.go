package user_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-iam/router"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserHTTPCRUDDenialsHaveZeroObservedGormAccess(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test", Password: "password", Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	var reads, writes atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("user-http-crud:observed-read", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("user-http-crud:observed-write", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trusted := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:write", "user:api:delete", "user:api:manage")
	if _, err := env.userService.GetHTTP(trusted, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.ExecuteHTTP(trusted, appcrud.ActionUpdate, user.ID, func(_ context.Context, item *iamentity.User) error { item.Avatar = "observed"; return nil }); err != nil {
		t.Fatal(err)
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatal("observers did not detect the successful service's actual database path")
	}
	reads.Store(0)
	writes.Store(0)
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(base, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{nil, base, trace,
		userAssociationPrincipal(t, env.tenantID, "opaque", "platform", "*:*:*"),
		userAssociationPrincipal(t, env.tenantID, "7", "department", "*:*:*"),
		userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:write", "user:api:delete"),
		userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:manage"),
	} {
		if _, err := env.userService.QueryHTTP(ctx, query.QueryOptions{}); err == nil {
			t.Fatal("list allowed an invalid entry identity/permission")
		}
		if _, err := env.userService.QueryCountHTTP(ctx, query.QueryOptions{}); err == nil {
			t.Fatal("count allowed an invalid entry identity/permission")
		}
		if _, err := env.userService.GetHTTP(ctx, user.ID); err == nil {
			t.Fatal("read allowed an invalid entry identity/permission")
		}
		if err := env.userService.UpdateHTTP(ctx, user); err == nil {
			t.Fatal("update allowed an invalid entry identity/permission")
		}
		if err := env.userService.DeleteHTTP(ctx, user.ID); err == nil {
			t.Fatal("delete allowed an invalid entry identity/permission")
		}
	}
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{base, trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:manage")} {
		for _, request := range []struct{ method, path, body string }{{"GET", "", ""}, {"GET", "/99", ""}, {"PUT", "/99", `{"version":0,"avatar":"denied"}`}, {"PUT", "/bulk", `[{"id":99,"version":0}]`}, {"DELETE", "/99", ""}, {"DELETE", "/bulk", `{"ids":[99]}`}} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(request.method, "/iam/users"+request.path, strings.NewReader(request.body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != 401 && rec.Code != 403 {
				t.Fatalf("%s %s status=%d body=%s", request.method, request.path, rec.Code, rec.Body.String())
			}
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied service/HTTP reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestUserHTTPExistingWriteFailureRollsBackWholeBatch(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	for i, name := range []string{"primary", "second"} {
		user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: name, Email: name + "@example.test", Password: "password", Status: "active"}
		user.ID = int64(i + 99)
		if err := env.db.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:write", "user:api:delete", "user:api:manage")
	var writes atomic.Int64
	if err := env.db.Callback().Update().Before("gorm:update").Register("user-http-existing:second-fault", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" && writes.Add(1) == 2 {
			tx.AddError(errors.NewCode(errors.Database, "second user write failed"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, body string }{
		{"PUT", `[{"id":99,"version":0,"username":"primary","email":"primary@example.test","avatar":"failed"},{"id":100,"version":0,"username":"second","email":"second@example.test","avatar":"failed"}]`},
		{"DELETE", `{"ids":[99,100]}`},
	} {
		writes.Store(0)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(request.method, "/iam/users/bulk", strings.NewReader(request.body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != 500 || writes.Load() != 2 {
			t.Fatalf("%s status=%d observedWrites=%d body=%s", request.method, rec.Code, writes.Load(), rec.Body.String())
		}
		for _, id := range []int64{99, 100} {
			var user iamentity.User
			if err := env.db.First(&user, id).Error; err != nil {
				t.Fatal(err)
			}
			if user.Version != 0 || user.Avatar != "" || user.DeletedAt != nil || user.Password != "password" {
				t.Fatalf("%s partial persistence=%+v", request.method, &user)
			}
		}
	}
}

func TestUserHTTPUpdateReadsCurrentEntityOnce(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	item := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "one-read", Email: "one-read@example.test", Password: "existing-password", Status: "active"}
	item.ID = 99
	if err := env.db.Create(item).Error; err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int64
	if err := env.db.Callback().Query().After("gorm:query").Register("user-http:current-reads", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" {
			reads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write", "user:api:manage")
	item.Password, item.Avatar = "", "first"
	if err := env.userService.UpdateHTTP(ctx, item); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || item.Version != 1 || item.Password != "existing-password" {
		t.Fatalf("reads=%d item=%+v", reads.Load(), item)
	}
	reads.Store(0)
	result, err := env.userService.ExecuteBulkHTTP(ctx, appcrud.ActionUpdate, []int64{item.ID}, func(_ context.Context, current *iamentity.User) error {
		current.Password, current.Avatar = "", "bulk"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || len(result) != 1 || result[0].Version != 2 || result[0].Password != "existing-password" {
		t.Fatalf("bulk reads=%d result=%+v", reads.Load(), result)
	}
}
