package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	iamauth "gochen-iam/auth"
	auth "gochen/auth"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx/nethttp"
)

func newTestHTTPContext(t *testing.T, method, path string, headers ...map[string]string) *nethttp.Context {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, "http://example.com"+path, nil)
	for _, h := range headers {
		for k, v := range h {
			r.Header.Set(k, v)
		}
	}
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatalf("NewBaseContext failed: %v", err)
	}
	return ctx
}

func TestOptionalAuthMiddleware_NoToken_PassThrough(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{SecretKey: "test-secret", TokenHeader: "Authorization", TokenPrefix: "Bearer "})
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	called := false
	if err := mw(ctx, func() error { called = true; return nil }); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestOptionalAuthMiddleware_InvalidToken_Returns401(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{SecretKey: "test-secret", TokenHeader: "Authorization", TokenPrefix: "Bearer "})
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users", map[string]string{"Authorization": "Bearer invalid-token"})

	if err := mw(ctx, func() error { return nil }); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestOptionalAuthMiddleware_FixedModeInjectsTenantWithoutHeaderOrToken(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "single-tenant")

	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	mw := OptionalAuthMiddleware(&AuthConfig{SecretKey: "test-secret", TokenHeader: "Authorization", TokenPrefix: "Bearer ", RequireTenant: true})
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	called := false
	err := mw(ctx, func() error {
		called = true
		if got := contextx.TenantID(ctx.RequestContext()); got != "single-tenant" {
			t.Fatalf("expected single-tenant, got %s", got)
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

func TestOptionalAuthMiddleware_RequiresTenantHeaderInTenantMode(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:       "test-secret",
		TokenHeader:     "Authorization",
		TokenPrefix:     "Bearer ",
		RequireTenant:   true,
		ContextResolver: fixedAuthContextResolver{kind: "tenant"},
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users", map[string]string{"Authorization": "Bearer " + token})

	if err := mw(ctx, func() error { return nil }); !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestOptionalAuthMiddleware_BindsTenantAndPrincipalFromToken(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := OptionalAuthMiddleware(&AuthConfig{
		SecretKey:       "test-secret",
		TokenHeader:     "Authorization",
		TokenPrefix:     "Bearer ",
		RequireTenant:   true,
		TenantHeader:    "X-Tenant-ID",
		ContextResolver: fixedAuthContextResolver{kind: "platform"},
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users", map[string]string{"Authorization": "Bearer " + token, "X-Tenant-ID": "tenant-b"})

	called := false
	err = mw(ctx, func() error {
		called = true
		if got := contextx.TenantID(ctx.RequestContext()); got != "tenant-b" {
			t.Fatalf("expected tenant-b in context, got %s", got)
		}
		principal, ok := auth.PrincipalFromContext(ctx.RequestContext())
		if !ok {
			t.Fatalf("expected principal in request context")
		}
		if principal.SubjectID != 1 || principal.ActiveScopeID != 101 {
			t.Fatalf("unexpected principal: %+v", principal)
		}
		if got := iamauth.ActiveScopeKind(ctx.RequestContext()); got != "platform" {
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

func TestAuthMiddleware_RequiresToken(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	mw := AuthMiddleware(&AuthConfig{SecretKey: "test-secret", TokenHeader: "Authorization", TokenPrefix: "Bearer "})
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users")
	if err := mw(ctx, func() error { return nil }); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestAuthMiddleware_AllowsPlatformScopeCrossTenantHeader(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:iam:test")

	token, err := GenerateToken(1, 101, "binding-v1", []string{"*:*:*"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := AuthMiddleware(&AuthConfig{
		SecretKey:       "test-secret",
		TokenHeader:     "Authorization",
		TokenPrefix:     "Bearer ",
		RequireTenant:   true,
		TenantHeader:    "X-Tenant-ID",
		ContextResolver: fixedAuthContextResolver{kind: "platform"},
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/users", map[string]string{"Authorization": "Bearer " + token, "X-Tenant-ID": "tenant-b"})

	called := false
	err = mw(ctx, func() error {
		called = true
		if got := contextx.TenantID(ctx.RequestContext()); got != "tenant-b" {
			t.Fatalf("expected tenant-b in context, got %s", got)
		}
		principal, ok := auth.PrincipalFromContext(ctx.RequestContext())
		if !ok {
			t.Fatalf("expected principal in request context")
		}
		if principal.ActiveScopeID != 101 {
			t.Fatalf("unexpected principal: %+v", principal)
		}
		if got := iamauth.ActiveScopeKind(ctx.RequestContext()); got != "platform" {
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

func TestAuthMiddleware_GlobalWildcardPassesPermissionMiddleware(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("api:task:read")

	token, err := GenerateToken(1, 101, "binding-v1", []string{"*:*:*"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mw := AuthMiddleware(&AuthConfig{
		SecretKey:       "test-secret",
		TokenHeader:     "Authorization",
		TokenPrefix:     "Bearer ",
		ContextResolver: fixedAuthContextResolver{kind: "platform"},
	})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/tasks", map[string]string{"Authorization": "Bearer " + token})

	called := false
	err = mw(ctx, func() error {
		return PermissionMiddleware(PermissionCode("api:task:read"))(ctx, func() error {
			called = true
			return nil
		})
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !called {
		t.Fatalf("expected permission middleware to pass with global wildcard")
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
	derived, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx.SetContext(ctx.RequestContext().WithContext(derived))
	if got := contextx.TenantID(ctx.RequestContext()); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", got)
	}
}

func TestPermissionMiddleware_UsesRegisteredRiskMetadataForRuntime(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	RegisterRequiredPermissionDefinitions(PermissionDefinition{Code: "api:task:write", RiskLevel: string(RiskLevelHigh)})

	ctx := newTestHTTPContext(t, "POST", "/api/v1/tasks")
	reqCtx, err := InjectClaimsRequestContext(ctx.RequestContext(), "tenant-a", &JWTClaims{
		UserID:        7,
		Permissions:   []string{"api:task:write"},
		ActiveScopeID: 200,
	}, fixedAuthContextResolver{kind: "tenant"})
	if err != nil {
		t.Fatalf("InjectClaimsRequestContext: %v", err)
	}
	ctx.SetContext(reqCtx)

	called := false
	err = PermissionMiddleware(PermissionCode("api:task:write"))(ctx, func() error {
		called = true
		if !auth.IsHighRiskAuthorizationFromContext(ctx.RequestContext()) {
			t.Fatalf("expected high-risk authorization marker to be present")
		}
		eval, err := auth.EvalContextFromContext(ctx.RequestContext())
		if err != nil {
			t.Fatalf("EvalContextFromContext: %v", err)
		}
		if eval.Consistency != auth.ConsistencyModeStrong {
			t.Fatalf("expected strong consistency, got %q", eval.Consistency)
		}
		if eval.Principal.SubjectID != 7 {
			t.Fatalf("expected subject 7, got %d", eval.Principal.SubjectID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("PermissionMiddleware: %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}

func TestPermissionMiddleware_DoesNotMarkLowRiskPermissionAsHighRisk(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	RegisterRequiredPermissionDefinitions(PermissionDefinition{Code: "api:task:read"})

	ctx := newTestHTTPContext(t, "GET", "/api/v1/tasks")
	reqCtx, err := InjectClaimsRequestContext(ctx.RequestContext(), "tenant-a", &JWTClaims{
		UserID:        8,
		Permissions:   []string{"api:task:read"},
		ActiveScopeID: 201,
	}, fixedAuthContextResolver{kind: "tenant"})
	if err != nil {
		t.Fatalf("InjectClaimsRequestContext: %v", err)
	}
	ctx.SetContext(reqCtx)

	called := false
	err = PermissionMiddleware(PermissionCode("api:task:read"))(ctx, func() error {
		called = true
		if auth.IsHighRiskAuthorizationFromContext(ctx.RequestContext()) {
			t.Fatalf("expected low-risk permission to avoid high-risk marker")
		}
		eval, err := auth.EvalContextFromContext(ctx.RequestContext())
		if err != nil {
			t.Fatalf("EvalContextFromContext: %v", err)
		}
		if eval.Principal.SubjectID != 8 {
			t.Fatalf("expected subject 8, got %d", eval.Principal.SubjectID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("PermissionMiddleware: %v", err)
	}
	if !called {
		t.Fatalf("expected next to be called")
	}
}
