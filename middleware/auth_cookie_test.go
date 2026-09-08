package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gochen-runtime/http/nethttp"
)

func TestExtractTokenPrefersHeaderThenCookie(t *testing.T) {
	cfg := &AuthConfig{
		SecretKey:             "secret",
		TokenHeader:           "Authorization",
		TokenPrefix:           "Bearer ",
		AccessTokenCookieName: AccessTokenCookieName,
		AccessTokenCookiePath: "/",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "cookie-token"})
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := extractToken(ctx, cfg); got != "cookie-token" {
		t.Fatalf("cookie token = %q", got)
	}

	r.Header.Set("Authorization", "Bearer header-token")
	ctx, err = nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := extractToken(ctx, cfg); got != "header-token" {
		t.Fatalf("header token = %q", got)
	}
}

func TestWriteAndClearAccessTokenCookie(t *testing.T) {
	cfg := DefaultAuthConfig()
	cfg.SecretKey = "secret"
	secure := false
	cfg.AccessTokenCookieSecure = &secure

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/auth/activate-scope", nil)
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	WriteAccessTokenCookie(ctx, "jwt-value", cfg)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != AccessTokenCookieName || cookies[0].Value != "jwt-value" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected cookies: %#v", cookies)
	}

	w2 := httptest.NewRecorder()
	ctx2, err := nethttp.NewBaseContext(w2, r)
	if err != nil {
		t.Fatal(err)
	}
	ClearAccessTokenCookie(ctx2, cfg)
	cleared := w2.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("expected expired cookie, got %#v", cleared)
	}
}

func TestEnsureCSRFCookieReusesRequestCookieOrIssuesOne(t *testing.T) {
	secure := false
	cfg := &AuthConfig{
		AccessTokenCookieName:   AccessTokenCookieName,
		AccessTokenCookieSecure: &secure,
		CSRFCookieName:          CSRFCookieName,
		CSRFCookiePath:          "/",
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/iam/auth/csrf", nil)
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	issued := EnsureCSRFCookie(ctx, cfg)
	if issued == "" {
		t.Fatal("expected a CSRF token")
	}
	if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != issued {
		t.Fatalf("unexpected issued cookies: %#v", cookies)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/iam/auth/csrf", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: issued})
	ctx, err = nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := EnsureCSRFCookie(ctx, cfg); got != issued {
		t.Fatalf("EnsureCSRFCookie() = %q, want existing token %q", got, issued)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("existing CSRF cookie should not be rewritten: %#v", cookies)
	}
}

func TestEmptyAccessTokenCookieNameDisablesCookieTransport(t *testing.T) {
	cfg := &AuthConfig{SecretKey: "secret", TokenHeader: "Authorization", TokenPrefix: "Bearer "}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "cookie-token"})
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}

	if got := extractToken(ctx, cfg); got != "" {
		t.Fatalf("cookie transport should be disabled, got token %q", got)
	}
	WriteAccessTokenCookie(ctx, "jwt-value", cfg)
	if token := WriteCSRFCookie(ctx, cfg); token != "" {
		t.Fatalf("cookie transport should not issue a CSRF token, got %q", token)
	}
	ClearAccessTokenCookie(ctx, cfg)
	ClearCSRFCookie(ctx, cfg)
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("cookie transport should not write cookies: %#v", cookies)
	}
}

func TestSetCookieOnContextAppendsMultipleCookies(t *testing.T) {
	secure := false
	cfg := DefaultAuthConfig()
	cfg.AccessTokenCookieSecure = &secure

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/auth/activate-scope", nil)
	ctx, err := nethttp.NewBaseContext(w, r)
	if err != nil {
		t.Fatal(err)
	}
	WriteAccessTokenCookie(ctx, "access-jwt", cfg)
	WriteCSRFCookie(ctx, cfg)
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected access and CSRF cookies, got %#v", cookies)
	}
	cookiesByKey := map[string]*http.Cookie{}
	for _, c := range cookies {
		cookiesByKey[c.Name+"@"+c.Path] = c
	}
	if cookiesByKey[AccessTokenCookieName+"@/"] == nil || cookiesByKey[CSRFCookieName+"@/"] == nil {
		t.Fatalf("missing cookies: %#v", cookies)
	}
	if cookiesByKey[CSRFCookieName+"@/"].HttpOnly {
		t.Fatal("csrf cookie must remain readable by the SPA")
	}
}
