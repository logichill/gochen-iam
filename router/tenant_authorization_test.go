package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	authz "gochen-runtime/host/authz"
	"gochen-runtime/http/nethttp"
	"gochen/errors"
)

type tenantAuthorizationRepo struct {
	routeScopedRepo[*iamentity.Tenant]
	writes int
}

func (r *tenantAuthorizationRepo) Create(_ context.Context, tenant *iamentity.Tenant) error {
	r.writes++
	tenant.ID = 42
	return nil
}

func (r *tenantAuthorizationRepo) Update(context.Context, *iamentity.Tenant) error {
	r.writes++
	return nil
}

func (r *tenantAuthorizationRepo) Delete(context.Context, int64) error {
	r.writes++
	return nil
}

func TestTenantCRUDRequiresActionPermission(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "default")
	read := svc.TenantPermissionSet.Code(iammw.ActionRead)
	write := svc.TenantPermissionSet.Code(iammw.ActionWrite)
	for _, tt := range []struct {
		name        string
		method      string
		path        string
		permissions []string
		allowed     bool
		writes      int
	}{
		{name: "create denied", method: "POST", path: "/tenants"},
		{name: "update denied", method: "PUT", path: "/tenants/:id", permissions: []string{read}},
		{name: "delete denied", method: "DELETE", path: "/tenants/:id", permissions: []string{read, write}},
		{name: "get denied", method: "GET", path: "/tenants/:id", permissions: []string{write}},
		{name: "list denied", method: "GET", path: "/tenants", permissions: []string{write}},
		{name: "create allowed", method: "POST", path: "/tenants", permissions: []string{write}, allowed: true, writes: 1},
		{name: "list allowed", method: "GET", path: "/tenants", permissions: []string{read}, allowed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &iamentity.Tenant{Key: "example", Name: "Example", Status: "inactive"}
			tenant.ID = 42
			repo := &tenantAuthorizationRepo{routeScopedRepo: routeScopedRepo[*iamentity.Tenant]{entity: tenant}}
			root := newRecordingGroup("", nil)
			if err := NewTenantRoutes(nil, repo, nil, nil, nil, nil, nil).RegisterRoutes(root); err != nil {
				t.Fatal(err)
			}
			base, err := authz.WithPrincipal(context.Background(), authz.Principal{SubjectID: 7, Permissions: tt.permissions})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{"key":"example","name":"Example"}`)).WithContext(base)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			ctx, err := nethttp.NewBaseContext(rec, req)
			if err != nil {
				t.Fatal(err)
			}
			ctx.SetParam("id", "42")
			handler := root.handlers[tt.method+" "+tt.path]
			if handler == nil {
				t.Fatal("missing tenant CRUD route")
			}
			err = iammw.PlatformScopeMiddleware()(ctx, func() error { return handler(ctx) })
			if tt.allowed {
				if err != nil || rec.Code >= http.StatusBadRequest {
					t.Fatalf("authorized request failed: status=%d err=%v body=%s", rec.Code, err, rec.Body.String())
				}
			} else if !errors.Is(err, errors.Forbidden) && rec.Code != http.StatusForbidden {
				t.Fatalf("unauthorized request: status=%d err=%v body=%s", rec.Code, err, rec.Body.String())
			}
			if repo.writes != tt.writes {
				t.Fatalf("repository writes = %d, want %d", repo.writes, tt.writes)
			}
		})
	}
}
