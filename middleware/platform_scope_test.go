package middleware

import (
	"testing"

	iamauth "gochen-iam/auth"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
)

func TestPlatformScopeMiddlewareSingleModeAcceptsAuthenticatedTenantScope(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "test-tenant")

	ctx := newTestHTTPContext(t, "GET", "/api/v1/iam/menus")
	requestCtx := bindPlatformScopeTestIdentity(t, ctx.RequestContext(), 7, "tenant")
	ctx.SetContext(requestCtx)
	called := false
	if err := PlatformScopeMiddleware()(ctx, func() error { called = true; return nil }); err != nil {
		t.Fatalf("expected single mode to accept authenticated tenant root scope: %v", err)
	}
	if !called {
		t.Fatal("expected next middleware to be called")
	}
}

func TestPlatformScopeMiddlewareTenantModeStillRejectsTenantScope(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	ctx := newTestHTTPContext(t, "GET", "/api/v1/iam/menus")
	requestCtx := bindPlatformScopeTestIdentity(t, ctx.RequestContext(), 7, "tenant")
	ctx.SetContext(requestCtx)
	if err := PlatformScopeMiddleware()(ctx, func() error { return nil }); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected tenant mode to reject non-platform scope, got %v", err)
	}
}

func bindPlatformScopeTestIdentity(t *testing.T, requestCtx httpx.IRequestContext, userID int64, scopeKind string) httpx.IRequestContext {
	t.Helper()
	derived, err := contextx.WithUserID(requestCtx, userID)
	if err != nil {
		t.Fatalf("WithUserID: %v", err)
	}
	bound := requestCtx.WithContext(derived)
	return iamauth.WithActiveScope(bound, 101, scopeKind)
}
