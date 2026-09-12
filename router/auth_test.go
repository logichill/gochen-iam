package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	auth "gochen-runtime/host/authz"
	"gochen-runtime/http/nethttp"
	"gochen/contextx"
	"gochen/errors"
)

type routerFixedAuthContextResolver struct {
	kind string
}

func (r routerFixedAuthContextResolver) ResolveAuthContext(ctx context.Context, claims *iammw.JWTClaims) (*iammw.ResolvedAuthContext, error) {
	_ = ctx
	return &iammw.ResolvedAuthContext{
		ActiveScopeID:   claims.ActiveScopeID,
		ActiveScopeKind: r.kind,
		VisibleScopeIDs: []int64{claims.ActiveScopeID},
	}, nil
}

type authRoutesUserServiceStub struct {
	registerFn     func(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error)
	authenticateFn func(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error)
	activateFn     func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error)
	snapshotFn     func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error)
}

func (s *authRoutesUserServiceStub) Register(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error) {
	if s.registerFn != nil {
		return s.registerFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (s *authRoutesUserServiceStub) Authenticate(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error) {
	if s.authenticateFn != nil {
		return s.authenticateFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (s *authRoutesUserServiceStub) ActivateScope(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
	if s.activateFn != nil {
		return s.activateFn(ctx, userID, activeScopeID)
	}
	return nil, nil
}

func (s *authRoutesUserServiceStub) AuthSnapshot(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
	if s.snapshotFn != nil {
		return s.snapshotFn(ctx, userID, activeScopeID)
	}
	return nil, nil
}

func (s *authRoutesUserServiceStub) ChangePassword(context.Context, int64, *svc.ChangePasswordRequest) error {
	return nil
}
func (s *authRoutesUserServiceStub) UpdateProfile(context.Context, int64, *svc.UpdateUserRequest) (*iamentity.User, error) {
	return nil, nil
}
func (s *authRoutesUserServiceStub) ActivateUser(context.Context, int64) error      { return nil }
func (s *authRoutesUserServiceStub) DeactivateUser(context.Context, int64) error    { return nil }
func (s *authRoutesUserServiceStub) LockUser(context.Context, int64) error          { return nil }
func (s *authRoutesUserServiceStub) UnlockUser(context.Context, int64) error        { return nil }
func (s *authRoutesUserServiceStub) AssignRole(context.Context, int64, int64) error { return nil }
func (s *authRoutesUserServiceStub) AssignRoleBinding(context.Context, int64, int64, *int64) error {
	return nil
}
func (s *authRoutesUserServiceStub) RemoveRole(context.Context, int64, int64) error { return nil }
func (s *authRoutesUserServiceStub) RemoveRoleBinding(context.Context, int64, int64) error {
	return nil
}
func (s *authRoutesUserServiceStub) AssignToGroup(context.Context, int64, int64) error { return nil }
func (s *authRoutesUserServiceStub) RemoveFromGroup(context.Context, int64, int64) error {
	return nil
}
func (s *authRoutesUserServiceStub) UserPermissions(context.Context, int64) ([]string, error) {
	return nil, nil
}
func (s *authRoutesUserServiceStub) CheckPermission(context.Context, int64, string) (bool, error) {
	return false, nil
}
func (s *authRoutesUserServiceStub) UserRoles(context.Context, int64) ([]*iamentity.Role, error) {
	return nil, nil
}
func (s *authRoutesUserServiceStub) UserRoleBindings(context.Context, int64) ([]*svc.UserRoleBindingDetail, error) {
	return nil, nil
}
func (s *authRoutesUserServiceStub) UserGroups(context.Context, int64) ([]*iamentity.Group, error) {
	return nil, nil
}
func (s *authRoutesUserServiceStub) UserProfile(context.Context, int64) (*iamentity.User, error) {
	return nil, nil
}

func newAuthJSONContext(t *testing.T, path string, body string, headers ...map[string]string) (*nethttp.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	ctx, err := nethttp.NewBaseContext(rec, req)
	if err != nil {
		t.Fatalf("NewBaseContext: %v", err)
	}
	return ctx, rec
}

func responseAccessToken(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data.Token == "" {
		t.Fatalf("response did not contain an access token: %s", recorder.Body.String())
	}
	return response.Data.Token
}

func TestAuthRoutesRefreshTokenUsesTenantHeaderAndScopeClaims(t *testing.T) {
	var gotTenant string
	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
			gotTenant = contextx.TenantID(ctx)
			principal, ok := auth.PrincipalFromContext(ctx)
			if !ok {
				t.Fatalf("expected principal in refresh context")
			}
			if principal.SubjectID != userID || principal.ActiveScopeID != activeScopeID {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			return &svc.ActiveScopeSession{UserID: userID, ActiveScopeID: activeScopeID, BindingVersion: "binding-v2", Permissions: []string{"read"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", AccessTokenTTL: time.Hour, TenantHeader: "X-Tenant-ID", ContextResolver: routerFixedAuthContextResolver{kind: "platform"}}

	token, err := iammw.GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`, map[string]string{"X-Tenant-ID": "tenant-b"})

	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if gotTenant != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", gotTenant)
	}
}

func TestNewAuthRoutesWithConfigKeepsInjectedConfig(t *testing.T) {
	config := &iammw.AuthConfig{SecretKey: "injected-secret", RevokedTokenStore: iammw.NewMemoryRevokedTokenStore()}
	routes := NewAuthRoutesWithConfig(&authRoutesUserServiceStub{}, config)
	if routes.authConfig != config {
		t.Fatal("auth routes did not retain the injected config")
	}
}

func TestAuthRoutesCSRFIssuesReadableBootstrapToken(t *testing.T) {
	secure := false
	routes := NewAuthRoutesWithConfig(&authRoutesUserServiceStub{}, &iammw.AuthConfig{
		AccessTokenCookieName:   iammw.AccessTokenCookieName,
		AccessTokenCookieSecure: &secure,
		CSRFCookieName:          iammw.CSRFCookieName,
		CSRFCookiePath:          "/",
	})
	ctx, recorder := newAuthJSONContext(t, "/api/v1/auth/csrf", "")
	if err := routes.csrfToken(ctx); err != nil {
		t.Fatalf("csrfToken: %v", err)
	}
	var response struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	token := response.Data["csrf_token"]
	if token == "" {
		t.Fatalf("missing csrf_token: %s", recorder.Body.String())
	}
	var found bool
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == iammw.CSRFCookieName && cookie.Value == token && !cookie.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("response did not set matching readable CSRF cookie: %#v", recorder.Result().Cookies())
	}
}

func TestAuthRoutesRefreshTokenRejectsRotatedTokenReplay(t *testing.T) {
	service := &authRoutesUserServiceStub{
		snapshotFn: func(context.Context, int64, int64) (*svc.ActiveScopeSession, error) {
			return &svc.ActiveScopeSession{UserID: 1, ActiveScopeID: 101, BindingVersion: "binding-v2", Permissions: []string{"read"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:         "test-secret",
		AccessTokenTTL:    time.Hour,
		TenantHeader:      "X-Tenant-ID",
		ContextResolver:   routerFixedAuthContextResolver{kind: "platform"},
		RevokedTokenStore: iammw.NewMemoryRevokedTokenStore(),
	}
	token, err := iammw.GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	body := `{"token":"` + token + `"}`
	headers := map[string]string{"X-Tenant-ID": "tenant-b"}
	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/refresh", body, headers)
	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("first refreshToken: %v", err)
	}
	ctx, _ = newAuthJSONContext(t, "/api/v1/auth/refresh", body, headers)
	if err := routes.refreshToken(ctx); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("expected replayed token to be unauthorized, got %v", err)
	}
}

func TestAuthRoutesRefreshTokenRejectsConcurrentReplay(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	service := &authRoutesUserServiceStub{
		snapshotFn: func(context.Context, int64, int64) (*svc.ActiveScopeSession, error) {
			arrived <- struct{}{}
			<-release
			return &svc.ActiveScopeSession{UserID: 1, ActiveScopeID: 101, BindingVersion: "binding-v2", Permissions: []string{"read"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:         "test-secret",
		AccessTokenTTL:    time.Hour,
		TenantHeader:      "X-Tenant-ID",
		ContextResolver:   routerFixedAuthContextResolver{kind: "platform"},
		RevokedTokenStore: iammw.NewMemoryRevokedTokenStore(),
	}
	token, err := iammw.GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	body := `{"token":"` + token + `"}`
	headers := map[string]string{"X-Tenant-ID": "tenant-b"}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			ctx, _ := newAuthJSONContext(t, "/api/v1/auth/refresh", body, headers)
			errs <- routes.refreshToken(ctx)
		}()
	}
	<-arrived
	<-arrived
	close(release)

	var succeeded, rejected int
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errors.Unauthorized):
			rejected++
		default:
			t.Fatalf("unexpected concurrent refresh error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent refresh results: succeeded=%d rejected=%d", succeeded, rejected)
	}
}

func TestAuthRoutesRefreshTokenFallsBackToInstalledResolver(t *testing.T) {
	previous := iammw.ResolveInstalledAuthContextResolver()
	iammw.InstallAuthContextResolver(routerFixedAuthContextResolver{kind: "platform"})
	t.Cleanup(func() {
		iammw.InstallAuthContextResolver(previous)
	})

	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
			principal, ok := auth.PrincipalFromContext(ctx)
			if !ok {
				t.Fatalf("expected principal in refresh context")
			}
			if principal.SubjectID != userID || principal.ActiveScopeID != activeScopeID {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			return &svc.ActiveScopeSession{UserID: userID, ActiveScopeID: activeScopeID, BindingVersion: "binding-v2", Permissions: []string{"read"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", AccessTokenTTL: time.Hour, TenantHeader: "X-Tenant-ID"}

	token, err := iammw.GenerateToken(1, 101, "binding-v1", []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`, map[string]string{"X-Tenant-ID": "tenant-b"})

	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
}

func TestAuthRoutesRegister_UsesTenantFromHeaderWhenRequired(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	var gotTenant string
	service := &authRoutesUserServiceStub{
		registerFn: func(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error) {
			gotTenant = tenantID
			if contextx.TenantID(ctx) != "tenant-a" {
				t.Fatalf("expected tenant-a in context, got %s", contextx.TenantID(ctx))
			}
			return &iamentity.User{TenantID: tenantID, Username: req.Username}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{RequireTenant: true, TenantHeader: "X-Tenant-ID"}

	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/register", `{"username":"tester","email":"tester@example.com","password":"secret123"}`, map[string]string{"X-Tenant-ID": "tenant-a"})

	if err := routes.register(ctx); err != nil {
		t.Fatalf("register: %v", err)
	}
	if gotTenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", gotTenant)
	}
}

func TestAuthRoutesLogin_ReturnsActivationToken(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	service := &authRoutesUserServiceStub{
		authenticateFn: func(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error) {
			return &svc.AuthenticateResult{
				UserID:         1,
				Username:       req.Username,
				BindingVersion: "binding-v1",
				AvailableScopes: []svc.AuthScopeOption{{
					ScopeID:     101,
					ScopeKey:    "platform",
					ScopeKind:   "platform",
					Permissions: []string{"*:*:*"},
				}},
			}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", ActivationTTL: time.Hour, RequireTenant: true, TenantHeader: "X-Tenant-ID"}

	ctx, rec := newAuthJSONContext(t, "/api/v1/auth/login", `{"username":"tester","password":"secret123"}`, map[string]string{"X-Tenant-ID": "tenant-a"})
	if err := routes.login(ctx); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "activation_token") {
		t.Fatalf("expected activation token in response, got %s", rec.Body.String())
	}
}

func TestAuthRoutesActivateScope_GeneratesAccessToken(t *testing.T) {
	service := &authRoutesUserServiceStub{
		activateFn: func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
			return &svc.ActiveScopeSession{UserID: userID, ActiveScopeID: activeScopeID, BindingVersion: "binding-v1", Permissions: []string{"*:*:*"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", AccessTokenTTL: 30 * time.Minute, AccessTokenCookieName: iammw.AccessTokenCookieName}

	activationToken, err := iammw.GenerateActivationToken(1, "binding-v1", []int64{101}, "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateActivationToken: %v", err)
	}
	ctx, rec := newAuthJSONContext(t, "/api/v1/auth/activate-scope", `{"activation_token":"`+activationToken+`","scope_id":101}`)
	if err := routes.activateScope(ctx); err != nil {
		t.Fatalf("activateScope: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("expected access token in response, got %s", rec.Body.String())
	}
	claims, err := iammw.ParseToken(responseAccessToken(t, rec), routes.authConfig.SecretKey)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 29*time.Minute || remaining > 31*time.Minute {
		t.Fatalf("access token TTL = %v, want about 30m", remaining)
	}
	var accessCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == iammw.AccessTokenCookieName {
			accessCookie = cookie
			break
		}
	}
	if accessCookie == nil || accessCookie.MaxAge != int((30*time.Minute).Seconds()) {
		t.Fatalf("access cookie = %#v, want MaxAge 1800", accessCookie)
	}
}

func TestAuthRoutesLogoutRevokesCurrentToken(t *testing.T) {
	store := iammw.NewMemoryRevokedTokenStore()
	routes := NewAuthRoutes(&authRoutesUserServiceStub{})
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:         "test-secret",
		TokenHeader:       "Authorization",
		TokenPrefix:       "Bearer ",
		RevokedTokenStore: store,
	}
	token, err := iammw.GenerateToken(7, 101, "binding-v1", nil, routes.authConfig.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/logout", "", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if err := routes.logout(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := iammw.ValidateAccessToken(t.Context(), token, routes.authConfig); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("logged-out token should be rejected, got %v", err)
	}
}

func TestAuthRoutesLogoutRequiresCSRFForValidCookieToken(t *testing.T) {
	secure := false
	routes := NewAuthRoutesWithConfig(&authRoutesUserServiceStub{}, &iammw.AuthConfig{
		SecretKey:                 "test-secret",
		AccessTokenCookieName:     iammw.AccessTokenCookieName,
		AccessTokenCookieSecure:   &secure,
		AccessTokenCookieSameSite: "lax",
		RevokedTokenStore:         iammw.NewMemoryRevokedTokenStore(),
	})
	token, err := iammw.GenerateToken(7, 101, "binding-v1", nil, routes.authConfig.SecretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/logout", "")
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.AccessTokenCookieName, Value: token})
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.CSRFCookieName, Value: "csrf-value"})
	if err := routes.logout(ctx); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected missing CSRF header to be forbidden, got %v", err)
	}
	if _, err := iammw.ValidateAccessToken(t.Context(), token, routes.authConfig); err != nil {
		t.Fatalf("CSRF rejection must not revoke the token: %v", err)
	}

	ctx, _ = newAuthJSONContext(t, "/api/v1/auth/logout", "", map[string]string{
		iammw.CSRFHeaderName: "csrf-value",
	})
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.AccessTokenCookieName, Value: token})
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.CSRFCookieName, Value: "csrf-value"})
	if err := routes.logout(ctx); err != nil {
		t.Fatalf("logout with matching CSRF token: %v", err)
	}
	if _, err := iammw.ValidateAccessToken(t.Context(), token, routes.authConfig); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("logged-out token should be rejected, got %v", err)
	}
}

func TestAuthRoutesLogoutClearsStaleCookieIdempotently(t *testing.T) {
	secure := false
	routes := NewAuthRoutesWithConfig(&authRoutesUserServiceStub{}, &iammw.AuthConfig{
		SecretKey:                 "test-secret",
		AccessTokenCookieName:     iammw.AccessTokenCookieName,
		AccessTokenCookieSecure:   &secure,
		AccessTokenCookieSameSite: "lax",
	})
	ctx, rec := newAuthJSONContext(t, "/api/v1/auth/logout", "")
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.AccessTokenCookieName, Value: "expired-or-invalid-token"})
	ctx.Request().AddCookie(&http.Cookie{Name: iammw.CSRFCookieName, Value: "stale-csrf-token"})
	if err := routes.logout(ctx); err != nil {
		t.Fatalf("logout with stale cookie: %v", err)
	}
	var accessCleared, csrfCleared bool
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == iammw.AccessTokenCookieName && cookie.MaxAge < 0 {
			accessCleared = true
		}
		if cookie.Name == iammw.CSRFCookieName && cookie.MaxAge < 0 {
			csrfCleared = true
		}
	}
	if !accessCleared {
		t.Fatal("logout did not clear the stale access cookie")
	}
	if !csrfCleared {
		t.Fatal("logout did not clear the stale CSRF cookie")
	}
}

func TestAuthRoutesActivateScope_RejectsMismatchedBindingVersion(t *testing.T) {
	service := &authRoutesUserServiceStub{
		activateFn: func(ctx context.Context, userID, activeScopeID int64) (*svc.ActiveScopeSession, error) {
			return &svc.ActiveScopeSession{UserID: userID, ActiveScopeID: activeScopeID, BindingVersion: "binding-v2", Permissions: []string{"*:*:*"}}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", AccessTokenTTL: time.Hour}

	activationToken, err := iammw.GenerateActivationToken(1, "binding-v1", []int64{101}, "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateActivationToken: %v", err)
	}
	ctx, _ := newAuthJSONContext(t, "/api/v1/auth/activate-scope", `{"activation_token":"`+activationToken+`","scope_id":101}`)
	err = routes.activateScope(ctx)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}
