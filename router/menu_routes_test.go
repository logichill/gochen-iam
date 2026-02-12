package router

import (
	"testing"

	httpx "gochen/httpx"
)

type recordingRouteGroup struct {
	prefix      string
	routes      map[string]struct{}
	middlewares int
}

func newRecordingGroup(prefix string, routes map[string]struct{}) *recordingRouteGroup {
	if routes == nil {
		routes = map[string]struct{}{}
	}
	return &recordingRouteGroup{prefix: prefix, routes: routes}
}

func (g *recordingRouteGroup) full(path string) string {
	return g.prefix + path
}

func (g *recordingRouteGroup) record(method, path string) {
	g.routes[method+" "+g.full(path)] = struct{}{}
}

func (g *recordingRouteGroup) GET(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("GET", path)
	return g
}
func (g *recordingRouteGroup) POST(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("POST", path)
	return g
}
func (g *recordingRouteGroup) PUT(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("PUT", path)
	return g
}
func (g *recordingRouteGroup) DELETE(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("DELETE", path)
	return g
}
func (g *recordingRouteGroup) PATCH(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("PATCH", path)
	return g
}
func (g *recordingRouteGroup) HEAD(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("HEAD", path)
	return g
}
func (g *recordingRouteGroup) OPTIONS(path string, handler httpx.Handler) httpx.IRouteGroup {
	g.record("OPTIONS", path)
	return g
}
func (g *recordingRouteGroup) Group(prefix string) httpx.IRouteGroup {
	return newRecordingGroup(g.prefix+prefix, g.routes)
}
func (g *recordingRouteGroup) Use(middleware ...httpx.Middleware) httpx.IRouteGroup {
	g.middlewares += len(middleware)
	return g
}

func TestMenuRoutes_RegisterRoutes(t *testing.T) {
	routes := map[string]struct{}{}
	root := newRecordingGroup("", routes)

	mr := NewMenuRoutes(nil)
	if err := mr.RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}

	want := []string{
		"GET /menus/me",
		"GET /menus",
		"POST /menus",
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
