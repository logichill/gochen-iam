package middleware

import (
	"net/http/httptest"
	"testing"

	"gochen/errorx"
	nethttp "gochen/httpx/nethttp"
)

func newTestHTTPContext(t *testing.T, method, path string) *nethttp.Context {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, "http://example.com"+path, nil)
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatalf("NewBaseContext failed: %v", err)
	}
	return ctx
}

func TestOptionalAuthMiddleware_NoToken_PassThrough(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:   "test-secret",
		TokenHeader: "Authorization",
		TokenPrefix: "Bearer ",
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	called := false
	err := mw(ctx, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestOptionalAuthMiddleware_InvalidToken_Returns401(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:   "test-secret",
		TokenHeader: "Authorization",
		TokenPrefix: "Bearer ",
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	ctx.GetRequest().Header.Set("Authorization", "Bearer invalid-token")

	called := false
	err := mw(ctx, func() error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errorx.Is(err, errorx.Unauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if called {
		t.Fatalf("expected next not to be called")
	}
}
