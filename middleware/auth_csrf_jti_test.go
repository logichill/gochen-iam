package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gochen/errors"
	"gochen/httpx/nethttp"
)

func TestCSRFDoubleSubmitEnforcedForCookieAuthMutations(t *testing.T) {
	secure := false
	cfg := &AuthConfig{
		SecretKey:                 "secret",
		AccessTokenCookieName:     AccessTokenCookieName,
		AccessTokenCookiePath:     "/api",
		AccessTokenCookieSecure:   &secure,
		CSRFCookieName:            CSRFCookieName,
		CSRFCookiePath:            "/",
		CSRFHeaderName:            CSRFHeaderName,
		AccessTokenCookieSameSite: "lax",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "access"})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-1"})
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnforceCSRFDoubleSubmit(ctx, cfg); err == nil {
		t.Fatal("expected CSRF failure without header")
	}

	r.Header.Set(CSRFHeaderName, "csrf-1")
	ctx, err = nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnforceCSRFDoubleSubmit(ctx, cfg); err != nil {
		t.Fatalf("expected csrf pass, got %v", err)
	}

	// Browsers can temporarily send both the retired /api cookie and the current / cookie.
	// The header must be allowed to match the readable current cookie, regardless of cookie order.
	r = httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "access"})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "legacy-csrf"})
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-current"})
	r.Header.Set(CSRFHeaderName, "csrf-current")
	ctx, err = nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnforceCSRFDoubleSubmit(ctx, cfg); err != nil {
		t.Fatalf("expected current CSRF cookie to pass alongside a legacy duplicate, got %v", err)
	}
}

func TestCSRFDoubleSubmitUsesConfiguredTokenHeader(t *testing.T) {
	secure := false
	cfg := &AuthConfig{
		SecretKey:                 "secret",
		TokenHeader:               "X-Access-Token",
		TokenPrefix:               "Token ",
		AccessTokenCookieName:     AccessTokenCookieName,
		AccessTokenCookieSecure:   &secure,
		AccessTokenCookieSameSite: "lax",
	}
	ctx := newTestHTTPContext(t, http.MethodPost, "/api/v1/resources", map[string]string{
		"X-Access-Token": "Token header-token",
	})
	ctx.Request().AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "stale-cookie-token"})

	if err := EnforceCSRFDoubleSubmit(ctx, cfg); err != nil {
		t.Fatalf("configured header authentication should not require CSRF: %v", err)
	}
}

func TestOptionalAuthSkipsPublicIAMAuthRoutesWithStaleCookie(t *testing.T) {
	cfg := DefaultAuthConfig()
	secure := false
	cfg.AccessTokenCookieSecure = &secure
	middleware := OptionalAuthMiddleware(cfg)

	for _, path := range []string{
		"/api/v1/iam/auth/login",
		"/api/v1/iam/auth/activate-scope",
		"/api/v1/iam/auth/register",
		"/api/v1/iam/auth/forgot-password",
		"/api/v1/iam/auth/reset-password",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
			r.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "stale-token"})
			ctx, err := nethttp.NewBaseContext(w, r)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err := middleware(ctx, func() error {
				called = true
				return nil
			}); err != nil {
				t.Fatalf("public route returned error: %v", err)
			}
			if !called {
				t.Fatal("public route did not reach next handler")
			}
		})
	}
}

func TestRevokedJTIIsRejected(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.SecretKey = "secret"
	secure := false
	cfg.AccessTokenCookieSecure = &secure
	store := newMemoryRevokedTokenStore()
	cfg.RevokedTokenStore = store

	token, err := GenerateToken(7, 1, "bv1", []string{"a:b:c"}, cfg.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseToken(token, cfg.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID == "" {
		t.Fatal("expected jti")
	}
	consumed, err := store.Consume(t.Context(), claims.ID, time.Now().Add(time.Hour))
	if err != nil || !consumed {
		t.Fatalf("Consume() = %v, %v", consumed, err)
	}
	if _, err := ValidateAccessToken(t.Context(), token, cfg); err == nil {
		t.Fatal("expected revoked token to fail")
	}
}

func TestMemoryRevokedTokenStoreConsumeIsAtomicAndBounded(t *testing.T) {
	store := newMemoryRevokedTokenStoreWithLimit(1)
	expiresAt := time.Now().Add(time.Hour)
	consumed, err := store.Consume(t.Context(), "first", expiresAt)
	if err != nil || !consumed {
		t.Fatalf("first Consume() = %v, %v", consumed, err)
	}
	consumed, err = store.Consume(t.Context(), "first", expiresAt)
	if err != nil || consumed {
		t.Fatalf("replayed Consume() = %v, %v", consumed, err)
	}
	if _, err := store.Consume(t.Context(), "second", expiresAt); !errors.Is(err, errors.ServiceUnavailable) {
		t.Fatalf("capacity error = %v, want ServiceUnavailable", err)
	}
}

func TestMemoryRevokedTokenStoreReclaimsExpiredCapacity(t *testing.T) {
	store := newMemoryRevokedTokenStoreWithLimit(1)
	consumed, err := store.Consume(t.Context(), "expired", time.Now().Add(-revokedTokenClockSkew-time.Second))
	if err != nil || !consumed {
		t.Fatalf("expired Consume() = %v, %v", consumed, err)
	}
	consumed, err = store.Consume(t.Context(), "current", time.Now().Add(time.Hour))
	if err != nil || !consumed {
		t.Fatalf("Consume() after expiry = %v, %v", consumed, err)
	}
	if revoked, err := store.IsRevoked(t.Context(), "expired"); err != nil || revoked {
		t.Fatalf("expired IsRevoked() = %v, %v", revoked, err)
	}
}
