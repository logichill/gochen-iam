package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	"gochen-iam/auth"
	ctxx "gochen/contextx"
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
	RegisterRequiredPermissions("api:iam:test")

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
	RegisterRequiredPermissions("api:iam:test")

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

func TestOptionalAuthMiddleware_FixedModeInjectsTenantWithoutHeaderOrToken(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "fixed")
	t.Setenv("IAM_FIXED_TENANT_ID", "fixed-tenant")

	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("api:iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:     "test-secret",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
		RequireTenant: true,
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	called := false
	err := mw(ctx, func() error {
		called = true
		if got := ctxx.GetTenantID(ctx.GetContext()); got != "fixed-tenant" {
			t.Fatalf("expected fixed-tenant, got %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestOptionalAuthMiddleware_UsesTenantFromTokenWhenHeaderMissing(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "required") // 测试 required 模式下从 token 读取 tenant

	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateToken(1, "tenant-a", "tester", []string{"user"}, []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:     "test-secret",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
		RequireTenant: true,
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	ctx.GetRequest().Header.Set("Authorization", "Bearer "+token)

	called := false
	err = mw(ctx, func() error {
		called = true
		if got := ctxx.GetTenantID(ctx.GetContext()); got != "tenant-a" {
			t.Fatalf("expected tenant-a in context, got %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestOptionalAuthMiddleware_RejectsTenantMismatchBetweenHeaderAndToken(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "required") // 测试 required 模式下的跨租户拒绝

	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateToken(1, "tenant-a", "tester", []string{"user"}, []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:     "test-secret",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
		RequireTenant: true,
		TenantHeader:  "X-Tenant-ID",
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	ctx.GetRequest().Header.Set("Authorization", "Bearer "+token)
	ctx.GetRequest().Header.Set("X-Tenant-ID", "tenant-b")

	err = mw(ctx, func() error { return nil })
	if !errorx.Is(err, errorx.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
}

func TestOptionalAuthMiddleware_AllowsPlatformScopeCrossTenantHeader(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "required")

	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateTokenWithScope(
		1,
		"platform-tenant",
		"platform-admin",
		[]string{"admin"},
		[]string{"*:*:*"},
		101,
		"/platform/",
		"platform",
		"test-secret",
		defaultAccessTokenTTL,
	)
	if err != nil {
		t.Fatalf("GenerateTokenWithScope: %v", err)
	}

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:     "test-secret",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
		RequireTenant: true,
		TenantHeader:  "X-Tenant-ID",
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	ctx.GetRequest().Header.Set("Authorization", "Bearer "+token)
	ctx.GetRequest().Header.Set("X-Tenant-ID", "tenant-b")

	called := false
	err = mw(ctx, func() error {
		called = true
		if got := ctxx.GetTenantID(ctx.GetContext()); got != "tenant-b" {
			t.Fatalf("expected tenant-b in context, got %s", got)
		}
		if got := auth.GetActiveScopeType(ctx.GetContext()); got != "platform" {
			t.Fatalf("expected platform active scope, got %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestAuthMiddleware_AllowsPlatformScopeCrossTenantHeader(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "required")

	resetRequiredPermissionsRegistryForTest()
	strictRegistryValidated = 0
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateTokenWithScope(
		1,
		"platform-tenant",
		"platform-admin",
		[]string{"admin"},
		[]string{"*:*:*"},
		101,
		"/platform/",
		"platform",
		"test-secret",
		defaultAccessTokenTTL,
	)
	if err != nil {
		t.Fatalf("GenerateTokenWithScope: %v", err)
	}

	mw := AuthMiddleware(&AuthConfig{
		SecretKey:     "test-secret",
		TokenHeader:   "Authorization",
		TokenPrefix:   "Bearer ",
		RequireTenant: true,
		TenantHeader:  "X-Tenant-ID",
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	ctx.GetRequest().Header.Set("Authorization", "Bearer "+token)
	ctx.GetRequest().Header.Set("X-Tenant-ID", "tenant-b")

	called := false
	err = mw(ctx, func() error {
		called = true
		if got := ctxx.GetTenantID(ctx.GetContext()); got != "tenant-b" {
			t.Fatalf("expected tenant-b in context, got %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestReadRequestTenantID_AllowsTenantQuery(t *testing.T) {
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users?tenant_id=tenant-q")
	cfg := &AuthConfig{TenantHeader: "X-Tenant-ID", AllowTenantQuery: true}
	if got := readRequestTenantID(ctx, cfg); got != "tenant-q" {
		t.Fatalf("expected tenant-q, got %s", got)
	}
}

func TestNewTestHTTPContextCarriesBaseContext(t *testing.T) {
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	derived, err := ctxx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx.SetContext(ctx.GetContext().WithContext(derived))
	if got := ctxx.GetTenantID(ctx.GetContext()); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", got)
	}
}
