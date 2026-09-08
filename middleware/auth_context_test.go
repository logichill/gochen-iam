package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	iamauth "gochen-iam/auth"
	auth "gochen-runtime/host/authz"
	"gochen/contextx"
	"gochen/httpx"
)

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
