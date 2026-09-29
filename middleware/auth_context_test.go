package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	iamauth "gochen-iam/auth"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
)

type authContextResolverFunc func(context.Context, *JWTClaims) (*ResolvedAuthContext, error)

func (f authContextResolverFunc) ResolveAuthContext(ctx context.Context, claims *JWTClaims) (*ResolvedAuthContext, error) {
	return f(ctx, claims)
}

func TestAuthMiddlewaresRequireTheirOwnResolver(t *testing.T) {
	RegisterRequiredPermissions("user:api:read")
	token, err := GenerateToken(7, 100, "binding-v1", []string{"user:api:read"}, "test-secret")
	require.NoError(t, err)
	for _, newMiddleware := range []func(*AuthConfig) httpx.Middleware{AuthMiddleware, OptionalAuthMiddleware} {
		configs := []*AuthConfig{DefaultAuthConfigForEnvironment("test"), DefaultAuthConfigForEnvironment("test"), DefaultAuthConfigForEnvironment("test")}
		for i, cfg := range configs {
			cfg.SecretKey = "test-secret"
			if i < 2 {
				cfg.ContextResolver = authContextResolverFunc(func(context.Context, *JWTClaims) (*ResolvedAuthContext, error) {
					return &ResolvedAuthContext{ActiveScopeID: int64(101 + i), ActiveScopeKind: "tenant", VisibleScopeIDs: []int64{int64(101 + i)}}, nil
				})
			}
		}
		for _, i := range []int{0, 1, 0, 2} {
			cfg := configs[i]
			ctx := newTestHTTPContext(t, "GET", "/private", map[string]string{"Authorization": "Bearer " + token})
			called := false
			err := newMiddleware(cfg)(ctx, func() error {
				called = true
				require.Equal(t, int64(101+i), iamauth.ActiveScopeIDFromContext(ctx.RequestContext()))
				return nil
			})
			if i == 2 {
				require.ErrorIs(t, err, errors.InvalidInput)
				require.False(t, called)
			} else {
				require.NoError(t, err)
				require.True(t, called)
			}
		}
	}
}

func TestInjectClaimsRequestContext_BindsTenantBeforeResolving(t *testing.T) {
	for _, existingTenant := range []string{"", "previous-tenant"} {
		t.Run("existing="+existingTenant, func(t *testing.T) {
			ctx := context.Background()
			if existingTenant != "" {
				var err error
				ctx, err = contextx.WithTenantID(ctx, existingTenant)
				require.NoError(t, err)
			}
			reqCtx, err := httpx.NewRequestContext(ctx)
			require.NoError(t, err)
			resolver := authContextResolverFunc(func(ctx context.Context, claims *JWTClaims) (*ResolvedAuthContext, error) {
				require.Equal(t, "tenant-b", contextx.TenantID(ctx))
				return fixedAuthContextResolver{}.ResolveAuthContext(ctx, claims)
			})
			bound, err := InjectClaimsRequestContext(reqCtx, " tenant-b ", &JWTClaims{UserID: 7, ActiveScopeID: 100}, resolver)
			require.NoError(t, err)
			require.Equal(t, "tenant-b", contextx.TenantID(bound))
		})
	}
}

func TestAuthMiddleware_ResolverFailureDoesNotCallHandler(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	RegisterRequiredPermissions("user:api:read")
	token, err := GenerateToken(7, 100, "binding-v1", []string{"user:api:read"}, "test-secret")
	require.NoError(t, err)
	resolverErr := errors.NewCode(errors.Forbidden, "tenant does not contain user")
	resolverCalled := false
	mw := AuthMiddleware(&AuthConfig{
		Environment:  "test",
		TenantPolicy: tenant.Policy{Mode: tenant.ModeTenant},
		SecretKey:    "test-secret", RequireTenant: true,
		TokenHeader: "Authorization", TokenPrefix: "Bearer ", TenantHeader: "X-Tenant-ID",
		ContextResolver: authContextResolverFunc(func(ctx context.Context, _ *JWTClaims) (*ResolvedAuthContext, error) {
			resolverCalled = true
			require.Equal(t, "tenant-b", contextx.TenantID(ctx))
			return nil, resolverErr
		}),
	})
	ctx := newTestHTTPContext(t, "GET", "/api/users", map[string]string{
		"Authorization": "Bearer " + token, "X-Tenant-ID": "tenant-b",
	})
	called := false
	err = mw(ctx, func() error { called = true; return nil })
	require.True(t, resolverCalled)
	require.ErrorIs(t, err, resolverErr)
	require.False(t, called)
}

func TestInjectClaimsRequestContext_BindsPrincipalAndLegacyHelpers(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	reqCtx, err := httpx.NewRequestContext(context.Background())
	require.NoError(t, err)

	bound, err := InjectClaimsRequestContext(reqCtx, "tenant-b", &JWTClaims{
		UserID:        7,
		Permissions:   []string{"user:api:manage", "*:*:*"},
		ActiveScopeID: 100,
	}, fixedAuthContextResolver{kind: "platform"})
	require.NoError(t, err)

	principal, ok := auth.PrincipalFromContext(bound)
	require.True(t, ok)
	require.Equal(t, int64(7), principal.SubjectID)
	require.Equal(t, int64(100), principal.ActiveScopeID)
	require.True(t, principal.HasPermission("user:api:manage"))
	require.Equal(t, "tenant-b", contextx.TenantID(bound))
	require.Equal(t, "platform", iamauth.ActiveScopeKind(bound))
	require.NotNil(t, iamauth.PermissionSet(bound))
	require.True(t, HasPermission(bound, "user:api:manage"))
	require.True(t, HasPermission(bound, "any:api:thing"))
}

func TestPermissionChecker_EmptyPermissionsFailClosed(t *testing.T) {
	reqCtx, err := httpx.NewRequestContext(context.Background())
	require.NoError(t, err)
	reqCtx = iamauth.WithPermissions(reqCtx, []string{"user:api:manage"})
	ctx := requestContextOnly{reqCtx: reqCtx}
	checker := permissionChecker{}

	require.False(t, HasPermission(reqCtx, ""))
	require.False(t, HasPermission(reqCtx, "   "))
	require.False(t, checker.HasAnyPermission(ctx, nil))
	require.False(t, checker.HasAnyPermission(ctx, []string{""}))
	require.False(t, checker.HasAnyPermission(ctx, []string{"   "}))
	require.True(t, checker.HasAnyPermission(ctx, []string{"user:api:manage"}))
	require.True(t, checker.HasAnyPermission(ctx, []string{"", "user:api:manage"}))
}

type requestContextOnly struct {
	httpx.IContext
	reqCtx httpx.IRequestContext
}

func (c requestContextOnly) RequestContext() httpx.IRequestContext {
	return c.reqCtx
}
