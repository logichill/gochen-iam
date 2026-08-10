package iam

import (
	"gochen/logging"
	"net/http"
	"net/http/httptest"
	"testing"

	iammw "gochen-iam/middleware"
	"gochen/db"
	"gochen/host/module"
	"gochen/httpx/nethttp"
)

func TestIAMModulePublicFeaturesExposeOnlyTenantMode(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "single")
	t.Setenv("IAM_SINGLE_TENANT_ID", "test-tenant")

	instance, err := NewModule(&moduleTestDatabase{}, logging.NewNoopLogger())
	if err != nil {
		t.Fatalf("NewModule(database) error: %v", err)
	}
	provider, ok := instance.(module.IPublicFeatureProvider)
	if !ok {
		t.Fatal("expected IAM module to implement IPublicFeatureProvider")
	}
	features := provider.PublicFeatures()
	if len(features) != 1 || features[0].Key != "tenant_mode" || features[0].Value != "single" {
		t.Fatalf("unexpected public features: %#v", features)
	}
}

func TestNewModuleRejectsNilDatabase(t *testing.T) {
	if _, err := NewModule(nil, logging.NewNoopLogger()); err == nil {
		t.Fatal("expected nil database to be rejected")
	}
}

type moduleTestDatabase struct{ db.IDatabase }

func TestIAMModuleAuthMiddlewareSkipsAnonymousRoutesAtAnyBasePath(t *testing.T) {
	t.Setenv("AUTH_SECRET", "iam-module-route-test-secret")
	t.Setenv("APP_ENV", "test")
	middleware := iamModuleAuthMiddleware(nil)
	for _, path := range []string{
		"/api/iam/auth/login",
		"/custom-api/identity/auth/register/",
		"/api/v1/iam/auth/forgot-password",
		"/api/iam/auth/logout",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
			request.AddCookie(&http.Cookie{Name: iammw.AccessTokenCookieName, Value: "stale-token"})
			ctx, err := nethttp.NewBaseContext(httptest.NewRecorder(), request)
			if err != nil {
				t.Fatalf("NewBaseContext: %v", err)
			}
			called := false
			if err := middleware(ctx, func() error { called = true; return nil }); err != nil {
				t.Fatalf("anonymous route returned error: %v", err)
			}
			if !called {
				t.Fatal("anonymous route did not reach handler")
			}
		})
	}
}

func TestIAMAnonymousAuthPathDoesNotSkipProtectedRoutes(t *testing.T) {
	for _, path := range []string{
		"/api/iam/auth/refresh",
		"/api/identity/login",
	} {
		if isIAMAnonymousAuthPath(path) {
			t.Fatalf("protected path was treated as anonymous: %s", path)
		}
	}
}
