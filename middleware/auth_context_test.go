package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	iamauth "gochen-iam/auth"
	"gochen/auth"
	"gochen/contextx"
	"gochen/httpx/nethttp"
)

func TestInjectClaimsRequestContext_BindsPrincipalAndLegacyHelpers(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	reqCtx, err := nethttp.NewRequestContext(context.Background())
	require.NoError(t, err)

	bound, err := InjectClaimsRequestContext(reqCtx, "tenant-b", &JWTClaims{
		UserID:        7,
		Permissions:   []string{"api:user:manage", "*:*:*"},
		ActiveScopeID: 100,
	}, fixedAuthContextResolver{kind: "platform"})
	require.NoError(t, err)

	principal, ok := auth.PrincipalFromContext(bound)
	require.True(t, ok)
	require.Equal(t, int64(7), principal.SubjectID)
	require.Equal(t, int64(100), principal.ActiveScopeID)
	require.True(t, principal.HasPermission("api:user:manage"))
	require.Equal(t, "tenant-b", contextx.TenantID(bound))
	require.Equal(t, "platform", iamauth.ActiveScopeKind(bound))
	require.NotNil(t, iamauth.PermissionSet(bound))
	require.True(t, HasPermission(bound, "api:user:manage"))
	require.True(t, HasPermission(bound, "api:any:thing"))
}
