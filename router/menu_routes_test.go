package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	menurepo "gochen-iam/repo/menu"
	svc "gochen-iam/service"
	menusvc "gochen-iam/service/menu"
	auth "gochen-runtime/host/authz"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/domain"
	"gochen/domain/spec"
	"gochen/testkit"
	"gorm.io/gorm"

	"gochen-runtime/http/nethttp"
	"gochen/httpx"
)

type menuRouteTestRepo struct {
	items []*iamentity.MenuItem
}

func (menuRouteTestRepo) Create(context.Context, *iamentity.MenuItem, spec.Spec) error { return nil }
func (menuRouteTestRepo) Update(context.Context, *iamentity.MenuItem, spec.Spec) error { return nil }
func (menuRouteTestRepo) Delete(context.Context, *iamentity.MenuItem, spec.Spec) error { return nil }
func (menuRouteTestRepo) Get(context.Context, int64, spec.Spec) (*iamentity.MenuItem, error) {
	return &iamentity.MenuItem{}, nil
}
func (r menuRouteTestRepo) List(_ context.Context, offset, limit int, _ spec.Spec) ([]*iamentity.MenuItem, error) {
	if offset >= len(r.items) {
		return nil, nil
	}
	return r.items[offset:min(offset+limit, len(r.items))], nil
}
func (r menuRouteTestRepo) Count(context.Context, spec.Spec) (int64, error) {
	return int64(len(r.items)), nil
}
func (menuRouteTestRepo) Exists(context.Context, int64, spec.Spec) (bool, error) {
	return false, nil
}
func (r menuRouteTestRepo) Query(ctx context.Context, opts query.QueryOptions, s spec.Spec) ([]*iamentity.MenuItem, error) {
	return r.List(ctx, opts.Offset, opts.Limit, s)
}
func (menuRouteTestRepo) QueryOne(context.Context, query.QueryOptions, spec.Spec) (*iamentity.MenuItem, error) {
	return &iamentity.MenuItem{}, nil
}
func (r menuRouteTestRepo) QueryCount(context.Context, query.QueryOptions, spec.Spec) (int64, error) {
	return int64(len(r.items)), nil
}
func (r menuRouteTestRepo) WithinTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type recordingRouteGroup struct {
	prefix           string
	routes           map[string]struct{}
	handlers         map[string]httpx.Handler
	routeMiddlewares map[string]int
	middlewares      int
}

func newRecordingGroup(prefix string, routes map[string]struct{}) *recordingRouteGroup {
	if routes == nil {
		routes = map[string]struct{}{}
	}
	return &recordingRouteGroup{prefix: prefix, routes: routes, handlers: map[string]httpx.Handler{}, routeMiddlewares: map[string]int{}}
}

func (g *recordingRouteGroup) full(path string) string {
	return g.prefix + path
}

func (g *recordingRouteGroup) record(method, path string, handler httpx.Handler) {
	route := method + " " + g.full(path)
	g.routes[route] = struct{}{}
	g.handlers[route] = handler
	g.routeMiddlewares[route] = g.middlewares
}

func (g *recordingRouteGroup) GET(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("GET", path, handler)
	return g
}
func (g *recordingRouteGroup) POST(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("POST", path, handler)
	return g
}
func (g *recordingRouteGroup) PUT(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("PUT", path, handler)
	return g
}
func (g *recordingRouteGroup) DELETE(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("DELETE", path, handler)
	return g
}
func (g *recordingRouteGroup) PATCH(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("PATCH", path, handler)
	return g
}
func (g *recordingRouteGroup) HEAD(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("HEAD", path, handler)
	return g
}
func (g *recordingRouteGroup) OPTIONS(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("OPTIONS", path, handler)
	return g
}
func (g *recordingRouteGroup) Group(prefix string) httpx.IRouteGroup {
	return &recordingRouteGroup{
		prefix:           g.prefix + prefix,
		routes:           g.routes,
		handlers:         g.handlers,
		routeMiddlewares: g.routeMiddlewares,
		middlewares:      g.middlewares,
	}
}
func (g *recordingRouteGroup) Use(middleware ...httpx.Middleware) httpx.IRouteGroup {
	g.middlewares += len(middleware)
	return g
}

type routeScopedRepo[T domain.IEntity[int64]] struct {
	entity T
}

func (r routeScopedRepo[T]) Create(context.Context, T, spec.Spec) error { return nil }
func (r routeScopedRepo[T]) Update(context.Context, T, spec.Spec) error { return nil }
func (r routeScopedRepo[T]) Delete(context.Context, T, spec.Spec) error {
	return nil
}
func (r routeScopedRepo[T]) Get(context.Context, int64, spec.Spec) (T, error) {
	return r.entity, nil
}
func (r routeScopedRepo[T]) List(context.Context, int, int, spec.Spec) ([]T, error) {
	return nil, nil
}
func (r routeScopedRepo[T]) Count(context.Context, spec.Spec) (int64, error) { return 0, nil }
func (r routeScopedRepo[T]) Exists(context.Context, int64, spec.Spec) (bool, error) {
	return false, nil
}
func (r routeScopedRepo[T]) Query(context.Context, query.QueryOptions, spec.Spec) ([]T, error) {
	return nil, nil
}
func (r routeScopedRepo[T]) QueryOne(context.Context, query.QueryOptions, spec.Spec) (T, error) {
	return r.entity, nil
}
func (r routeScopedRepo[T]) QueryCount(context.Context, query.QueryOptions, spec.Spec) (int64, error) {
	return 0, nil
}
func (r routeScopedRepo[T]) WithinTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func menuRoutesFixture(t *testing.T) (*MenuRoutes, *gorm.DB) {
	t.Helper()
	svc.RegisterIAMPermissionCatalog()
	_, storage, scopes := scopeRoutesFixture(t)
	if err := storage.AutoMigrate(&iamentity.MenuItem{}); err != nil {
		t.Fatal(err)
	}
	repo, err := menurepo.NewMenuItemRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	service, err := menusvc.NewMenuService(repo, svc.NewIAMAccess(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewMenuRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	return routes, storage
}

func TestMenuRoutes_RegisterRoutes(t *testing.T) {
	routes := map[string]struct{}{}
	root := newRecordingGroup("", routes)

	mr, _ := menuRoutesFixture(t)
	if err := mr.RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}

	want := []string{
		"GET /menus/me",
		"GET /menus",
		"GET /menus/:id",
		"POST /menus",
		"POST /menus/sync",
		"PUT /menus/:id",
		"DELETE /menus/:id",
		"POST /menus/:id/restore",
		"DELETE /menus/:id/purge",
		"POST /menus/:id/publish",
		"POST /menus/:id/unpublish",
	}
	for _, w := range want {
		if _, ok := routes[w]; !ok {
			t.Fatalf("missing route: %s", w)
		}
	}

	// 已移除 tenant override 相关路由
	if _, ok := routes["GET /menus/tenants/:tenant_id/overrides"]; ok {
		t.Fatalf("unexpected tenant override route registered")
	}
}

func TestMenuRoutes_ListIgnoresPagination(t *testing.T) {
	mr, storage := menuRoutesFixture(t)
	for id := int64(1); id <= 15; id++ {
		item := &iamentity.MenuItem{Code: fmt.Sprintf("item-%d", id), Title: fmt.Sprintf("Item %d", id), Type: iamentity.MenuTypePage}
		item.SetID(id)
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	root := newRecordingGroup("", nil)
	if err := mr.RegisterRoutes(root); err != nil {
		t.Fatal(err)
	}
	handler := root.handlers["GET /menus"]
	if handler == nil {
		t.Fatal("missing menu list handler")
	}
	for _, url := range []string{"/menus", "/menus?page=2&size=1", "/menus?page_size=1", "/menus?page=bad&size=0"} {
		t.Run(url, func(t *testing.T) {
			rec := httptest.NewRecorder()
			base, err := auth.WithPrincipal(context.Background(), auth.Principal{SubjectID: "1", IsSystem: true, ActiveScopeID: 1})
			if err != nil {
				t.Fatal(err)
			}
			base = iamauth.BindActiveScopeContext(base, 1, iamentity.ScopeTypePlatform)
			ctx, err := nethttp.NewBaseContext(rec, httptest.NewRequest(http.MethodGet, url, nil).WithContext(base))
			if err != nil {
				t.Fatal(err)
			}
			if err := handler(ctx); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
			}
			var response struct {
				Data []*iamentity.MenuItem `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Data) != 15 {
				t.Fatalf("returned %d menus, want 15", len(response.Data))
			}
			for i, item := range response.Data {
				if item.GetID() != int64(i+1) {
					t.Errorf("menu %d has ID %d, want %d", i, item.GetID(), i+1)
				}
			}
		})
	}
}

func TestManagementCRUDRoutesUseManageMiddlewareGroup(t *testing.T) {
	tests := []struct {
		name   string
		routes func(*recordingRouteGroup) error
		want   []string
	}{
		{
			name: "user",
			routes: func(root *recordingRouteGroup) error {
				routes, _ := userAssociationRoutesFixture(t)
				return routes.RegisterRoutes(root)
			},
			want: []string{
				"GET /users",
				"GET /users/:id",
				"POST /users",
				"PUT /users/:id",
				"DELETE /users/:id",
			},
		},
		{
			name: "group",
			routes: func(root *recordingRouteGroup) error {
				routes := groupAssociationRoutesFixture(t)
				return routes.RegisterRoutes(root)
			},
			want: []string{
				"GET /groups",
				"GET /groups/:id",
				"POST /groups",
				"PUT /groups/:id",
				"DELETE /groups/:id",
			},
		},
		{
			name: "role",
			routes: func(root *recordingRouteGroup) error {
				routes, _ := roleRoutesFixture(t)
				return routes.RegisterRoutes(root)
			},
			want: []string{
				"GET /roles",
				"GET /roles/:id",
				"POST /roles",
				"PUT /roles/:id",
				"DELETE /roles/:id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRecordingGroup("", nil)
			if err := tt.routes(root); err != nil {
				t.Fatalf("RegisterRoutes failed: %v", err)
			}
			for _, route := range tt.want {
				if _, ok := root.routes[route]; !ok {
					t.Fatalf("missing route: %s", route)
				}
				if got := root.routeMiddlewares[route]; got == 0 {
					t.Fatalf("route %s was registered without %s manage middleware", route, tt.name)
				}
			}
		})
	}
}

func TestTenantRoutesListUsesScopedQueryRepository(t *testing.T) {
	routes, storage := tenantRoutesFixture(t)
	if err := storage.Create(&iamentity.Tenant{Key: "listed", Name: "Listed", Status: "inactive"}).Error; err != nil {
		t.Fatal(err)
	}

	root := newRecordingGroup("", nil)
	if err := routes.RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}
	handler := root.handlers["GET /tenants"]
	if handler == nil {
		t.Fatalf("missing tenant list handler")
	}

	baseCtx, err := auth.WithPrincipal(context.Background(), auth.Principal{SubjectID: "1", ActiveScopeID: 1, IsSystem: true})
	if err != nil {
		t.Fatalf("WithPrincipal failed: %v", err)
	}
	baseCtx = iamauth.BindActiveScopeContext(baseCtx, 1, iamentity.ScopeTypePlatform)
	req := httptest.NewRequest(http.MethodGet, "/tenants?page=1&size=10", nil).WithContext(baseCtx)
	rec := httptest.NewRecorder()
	ctx, err := nethttp.NewBaseContext(rec, req)
	if err != nil {
		t.Fatalf("NewBaseContext failed: %v", err)
	}

	if err := handler(ctx); err != nil {
		t.Fatalf("tenant list handler failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant list status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"key":"listed"`) {
		t.Fatalf("tenant list omitted persisted row: %s", rec.Body.String())
	}
}

var (
	_ appcrud.Repository[*iamentity.User, int64]   = routeScopedRepo[*iamentity.User]{}
	_ appcrud.Repository[*iamentity.Group, int64]  = routeScopedRepo[*iamentity.Group]{}
	_ appcrud.Repository[*iamentity.Role, int64]   = routeScopedRepo[*iamentity.Role]{}
	_ appcrud.Repository[*iamentity.Tenant, int64] = routeScopedRepo[*iamentity.Tenant]{}
)
