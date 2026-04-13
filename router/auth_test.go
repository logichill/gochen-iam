package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen/authz"
	ctxx "gochen/contextx"
	"gochen/errorx"
	"gochen/httpx"
	nethttp "gochen/httpx/nethttp"
)

type authRoutesUserServiceStub struct {
	registerFn     func(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error)
	authenticateFn func(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error)
	snapshotFn     func(ctx context.Context, userID int64) (*svc.AuthenticateResult, error)
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

func (s *authRoutesUserServiceStub) AuthSnapshot(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
	return s.snapshotFn(ctx, userID)
}

func (s *authRoutesUserServiceStub) ChangePassword(context.Context, int64, *svc.ChangePasswordRequest) error {
	return nil
}

func (s *authRoutesUserServiceStub) UpdateProfile(context.Context, int64, *svc.UpdateUserRequest) (*iamentity.User, error) {
	return nil, nil
}

func (s *authRoutesUserServiceStub) ActivateUser(context.Context, int64) error { return nil }

func (s *authRoutesUserServiceStub) DeactivateUser(context.Context, int64) error { return nil }

func (s *authRoutesUserServiceStub) LockUser(context.Context, int64) error { return nil }

func (s *authRoutesUserServiceStub) UnlockUser(context.Context, int64) error { return nil }

func (s *authRoutesUserServiceStub) AssignRole(context.Context, int64, int64) error { return nil }

func (s *authRoutesUserServiceStub) RemoveRole(context.Context, int64, int64) error { return nil }

func (s *authRoutesUserServiceStub) AssignToGroup(context.Context, int64, int64) error { return nil }

func (s *authRoutesUserServiceStub) RemoveFromGroup(context.Context, int64, int64) error { return nil }

func (s *authRoutesUserServiceStub) UserPermissions(context.Context, int64) ([]string, error) {
	return nil, nil
}

func (s *authRoutesUserServiceStub) CheckPermission(context.Context, int64, string) (bool, error) {
	return false, nil
}

func (s *authRoutesUserServiceStub) SearchUsers(context.Context, string, int) ([]*iamentity.User, error) {
	return nil, nil
}

func (s *authRoutesUserServiceStub) UsersByStatus(context.Context, string) ([]*iamentity.User, error) {
	return nil, nil
}

func (s *authRoutesUserServiceStub) UserRoles(context.Context, int64) ([]*iamentity.Role, error) {
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

func TestAuthRoutesRefreshTokenUsesTenantFromToken(t *testing.T) {
	var gotTenant string
	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
			gotTenant = ctxx.TenantID(ctx)
			principal, ok := authz.PrincipalFromContext(ctx)
			if !ok {
				t.Fatalf("expected principal in refresh context")
			}
			if principal.SubjectID != userID || principal.TenantID != "tenant-a" {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			if !principal.HasPermission("read") {
				t.Fatalf("expected read permission in principal")
			}
			return &svc.AuthenticateResult{
				UserID:   userID,
				TenantID: gotTenant,
				Username: "tester",
			}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:      "test-secret",
		AccessTokenTTL: time.Hour,
	}

	token, err := iammw.GenerateToken(1, "tenant-a", "tester", []string{"user"}, []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if gotTenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", gotTenant)
	}
}

func TestAuthRoutesRefreshTokenRejectsTenantMismatch(t *testing.T) {
	called := false
	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
			called = true
			return nil, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:      "test-secret",
		AccessTokenTTL: time.Hour,
	}

	token, err := iammw.GenerateToken(1, "tenant-a", "tester", []string{"user"}, []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-b")
	routes.authConfig.TenantHeader = "X-Tenant-ID"

	err = routes.refreshToken(ctx)
	if !errorx.Is(err, errorx.Forbidden) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
	if called {
		t.Fatalf("expected service not to be called on tenant mismatch")
	}
}

func TestAuthRoutesRefreshTokenUsesTenantFromHeaderWhenMatched(t *testing.T) {
	var gotTenant string
	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
			gotTenant = ctxx.TenantID(ctx)
			return &svc.AuthenticateResult{
				UserID:   userID,
				TenantID: gotTenant,
				Username: "tester",
			}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:      "test-secret",
		AccessTokenTTL: time.Hour,
		TenantHeader:   "X-Tenant-ID",
	}

	token, err := iammw.GenerateToken(1, "tenant-a", "tester", []string{"user"}, []string{"read"}, "test-secret")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-a")

	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if gotTenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", gotTenant)
	}
}

func TestAuthRoutesRefreshTokenAllowsPlatformScopeCrossTenantHeader(t *testing.T) {
	var gotTenant string
	var gotScopeType string
	service := &authRoutesUserServiceStub{
		snapshotFn: func(ctx context.Context, userID int64) (*svc.AuthenticateResult, error) {
			gotTenant = ctxx.TenantID(ctx)
			principal, ok := authz.PrincipalFromContext(ctx)
			if !ok {
				t.Fatalf("expected principal in refresh context")
			}
			if principal.TenantID != "tenant-b" || principal.ActiveScopeType != "platform" {
				t.Fatalf("unexpected principal: %+v", principal)
			}
			if reqCtx, ok := ctx.(httpx.IRequestContext); ok {
				gotScopeType = iamauth.ActiveScopeType(reqCtx)
			}
			if _, err := svc.RequireTenantMatch(ctx, "platform-tenant"); err != nil {
				return nil, err
			}
			return &svc.AuthenticateResult{
				UserID:          userID,
				TenantID:        "platform-tenant",
				Username:        "tester",
				ActiveScopeID:   101,
				ActiveScopeCode: "/platform/",
				ActiveScopeType: "platform",
			}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:      "test-secret",
		AccessTokenTTL: time.Hour,
		TenantHeader:   "X-Tenant-ID",
	}

	token, err := iammw.GenerateTokenWithScope(
		1,
		"platform-tenant",
		"tester",
		[]string{"admin"},
		[]string{"*:*:*"},
		101,
		"/platform/",
		"platform",
		"test-secret",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("GenerateTokenWithScope: %v", err)
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/refresh", `{"token":"`+token+`"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-b")

	if err := routes.refreshToken(ctx); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if gotTenant != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", gotTenant)
	}
	if gotScopeType != "platform" {
		t.Fatalf("expected platform scope, got %s", gotScopeType)
	}
}

func TestAuthRoutesRegister_UsesTenantFromHeaderWhenRequired(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	var gotTenant string
	service := &authRoutesUserServiceStub{
		registerFn: func(ctx context.Context, tenantID string, req *svc.RegisterRequest) (*iamentity.User, error) {
			gotTenant = tenantID
			if ctxx.TenantID(ctx) != "tenant-a" {
				t.Fatalf("expected tenant-a in context, got %s", ctxx.TenantID(ctx))
			}
			return &iamentity.User{TenantID: tenantID, Username: req.Username}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		RequireTenant: true,
		TenantHeader:  "X-Tenant-ID",
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/register", `{"username":"tester","email":"tester@example.com","password":"secret123"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-a")

	if err := routes.register(ctx); err != nil {
		t.Fatalf("register: %v", err)
	}
	if gotTenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", gotTenant)
	}
}

func TestAuthRoutesLogin_UsesTenantFromHeaderWhenRequired(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	var gotTenant string
	service := &authRoutesUserServiceStub{
		authenticateFn: func(ctx context.Context, tenantID string, req *svc.AuthenticateRequest) (*svc.AuthenticateResult, error) {
			gotTenant = tenantID
			if ctxx.TenantID(ctx) != "tenant-a" {
				t.Fatalf("expected tenant-a in context, got %s", ctxx.TenantID(ctx))
			}
			return &svc.AuthenticateResult{
				UserID:      1,
				TenantID:    tenantID,
				Username:    req.Username,
				Permissions: []string{"read"},
			}, nil
		},
	}
	routes := NewAuthRoutes(service)
	routes.authConfig = &iammw.AuthConfig{
		SecretKey:      "test-secret",
		AccessTokenTTL: time.Hour,
		RequireTenant:  true,
		TenantHeader:   "X-Tenant-ID",
	}

	ctx := newAuthJSONContext(t, "/api/v1/auth/login", `{"username":"tester","password":"secret123"}`)
	ctx.Request().Header.Set("X-Tenant-ID", "tenant-a")

	if err := routes.login(ctx); err != nil {
		t.Fatalf("login: %v", err)
	}
	if gotTenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", gotTenant)
	}
}
