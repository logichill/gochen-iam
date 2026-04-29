package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	auth "gochen/auth/core"
	"gochen/contextx"
	"gochen/errors"
	nethttp "gochen/httpx/nethttp"
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

func newAuthJSONContext(t *testing.T, path string, body string) *nethttp.Context {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx, err := nethttp.NewBaseContext(rec, req)
	if err != nil {
		t.Fatalf("NewBaseContext: %v", err)
	}
	return ctx
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

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-b")

	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if gotTenant != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", gotTenant)
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

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-b")

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

	ctx := newAuthJSONContext(t, "/api/v1/auth/register", `{"username":"tester","email":"tester@example.com","password":"secret123"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-a")

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

	ctx := newAuthJSONContext(t, "/api/v1/auth/login", `{"username":"tester","password":"secret123"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-a")
	if err := routes.login(ctx); err != nil {
		t.Fatalf("login: %v", err)
	}
	rec := ctx.ResponseWriter().(*httptest.ResponseRecorder)
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
	routes.authConfig = &iammw.AuthConfig{SecretKey: "test-secret", AccessTokenTTL: time.Hour}

	activationToken, err := iammw.GenerateActivationToken(1, "binding-v1", []int64{101}, "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateActivationToken: %v", err)
	}
	ctx := newAuthJSONContext(t, "/api/v1/auth/activate-scope", `{"activation_token":"`+activationToken+`","scope_id":101}`)
	if err := routes.activateScope(ctx); err != nil {
		t.Fatalf("activateScope: %v", err)
	}
	rec := ctx.ResponseWriter().(*httptest.ResponseRecorder)
	if !strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("expected access token in response, got %s", rec.Body.String())
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
	ctx := newAuthJSONContext(t, "/api/v1/auth/activate-scope", `{"activation_token":"`+activationToken+`","scope_id":101}`)
	err = routes.activateScope(ctx)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}
