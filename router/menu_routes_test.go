package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	menusvc "gochen-iam/service/menu"
	auth "gochen/auth"
	"gochen/domain"
	"gochen/domain/access"
	"gochen/httpx"
	"gochen/httpx/nethttp"
	"gochen/ident"
)

type menuRouteTestRepo struct{}

func (menuRouteTestRepo) Create(context.Context, *iamentity.MenuItem) error { return nil }
func (menuRouteTestRepo) Update(context.Context, *iamentity.MenuItem) error { return nil }
func (menuRouteTestRepo) Delete(context.Context, int64) error               { return nil }
func (menuRouteTestRepo) Get(context.Context, int64) (*iamentity.MenuItem, error) {
	return &iamentity.MenuItem{}, nil
}
func (menuRouteTestRepo) List(context.Context, int, int) ([]*iamentity.MenuItem, error) {
	return nil, nil
}
func (menuRouteTestRepo) Count(context.Context) (int64, error) { return 0, nil }
func (menuRouteTestRepo) Exists(context.Context, int64) (bool, error) {
	return false, nil
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

func (r routeScopedRepo[T]) Create(context.Context, T) error { return nil }
func (r routeScopedRepo[T]) Update(context.Context, T) error { return nil }
func (r routeScopedRepo[T]) Delete(context.Context, int64) error {
	return nil
}
func (r routeScopedRepo[T]) Get(context.Context, int64) (T, error) {
	return r.entity, nil
}
func (r routeScopedRepo[T]) List(context.Context, int, int) ([]T, error) {
	return nil, nil
}
func (r routeScopedRepo[T]) Count(context.Context) (int64, error) { return 0, nil }
func (r routeScopedRepo[T]) Exists(context.Context, int64) (bool, error) {
	return false, nil
}
func (r routeScopedRepo[T]) ResolveResourceByID(context.Context, int64) (access.ResourceBoundary, error) {
	return access.ResourceBoundary{}, nil
}
func (r routeScopedRepo[T]) CreateWithConstraint(context.Context, T, iamaccess.WriteConstraint) error {
	return nil
}
func (r routeScopedRepo[T]) UpdateWithConstraint(context.Context, T, iamaccess.WriteConstraint) error {
	return nil
}
func (r routeScopedRepo[T]) DeleteWithConstraint(context.Context, int64, iamaccess.WriteConstraint) error {
	return nil
}

func TestMenuRoutes_RegisterRoutes(t *testing.T) {
	routes := map[string]struct{}{}
	root := newRecordingGroup("", routes)

	mr := NewMenuRoutes(&menusvc.MenuService{}, menuRouteTestRepo{}, nil)
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

func TestManagementCRUDRoutesUseManageMiddlewareGroup(t *testing.T) {
	tests := []struct {
		name   string
		routes func(*recordingRouteGroup) error
		want   []string
	}{
		{
			name: "user",
			routes: func(root *recordingRouteGroup) error {
				repo := routeScopedRepo[*iamentity.User]{entity: &iamentity.User{}}
				return NewUserRoutes(nil, repo, nil).RegisterRoutes(root)
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
				repo := routeScopedRepo[*iamentity.Group]{entity: &iamentity.Group{}}
				return NewGroupRoutes(nil, repo, nil).RegisterRoutes(root)
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
				repo := routeScopedRepo[*iamentity.Role]{entity: &iamentity.Role{}}
				return NewRoleRoutes(nil, repo, nil, nil).RegisterRoutes(root)
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
	repo := routeScopedRepo[*iamentity.Tenant]{entity: &iamentity.Tenant{}}
	authorizer, err := auth.NewAuthorizer(auth.EvaluatorFunc(func(
		context.Context,
		auth.Principal,
		string,
		[]auth.Resource,
	) (auth.AuthzDecision, error) {
		return auth.AllowDecision(), nil
	}), nil, ident.NewUUIDGenerator())
	if err != nil {
		t.Fatalf("NewAuthorizer failed: %v", err)
	}

	root := newRecordingGroup("", nil)
	if err := NewTenantRoutes(nil, repo, nil, nil, nil, nil, nil, authorizer).RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}
	handler := root.handlers["GET /tenants"]
	if handler == nil {
		t.Fatalf("missing tenant list handler")
	}

	baseCtx, err := auth.WithPrincipal(context.Background(), auth.Principal{SubjectID: 1, IsSystem: true})
	if err != nil {
		t.Fatalf("WithPrincipal failed: %v", err)
	}
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
}

var (
	_ svc.IScopedResourceContextRepository[*iamentity.User, int64]   = routeScopedRepo[*iamentity.User]{}
	_ svc.IScopedResourceContextRepository[*iamentity.Group, int64]  = routeScopedRepo[*iamentity.Group]{}
	_ svc.IScopedResourceContextRepository[*iamentity.Role, int64]   = routeScopedRepo[*iamentity.Role]{}
	_ svc.IScopedResourceContextRepository[*iamentity.Tenant, int64] = routeScopedRepo[*iamentity.Tenant]{}
)
