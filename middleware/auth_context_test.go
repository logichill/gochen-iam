package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	iamauth "gochen-iam/auth"
	"gochen/authz"
	hbasic "gochen/httpx/nethttp"
)

func TestInjectClaimsRequestContext_BindsPrincipalAndLegacyHelpers(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	reqCtx, err := hbasic.NewRequestContext(context.Background())
	require.NoError(t, err)

	bound, err := InjectClaimsRequestContext(reqCtx, "tenant-b", &JWTClaims{
		UserID:          7,
		TenantID:        "tenant-a",
		Roles:           []string{"admin"},
		Permissions:     []string{"api:user:manage", "*:*:*"},
		ActiveScopeID:   100,
		ActiveScopeCode: "/platform/",
		ActiveScopeType: "platform",
	})
	require.NoError(t, err)

	principal, ok := authz.PrincipalFromContext(bound)
	require.True(t, ok)
	require.Equal(t, int64(7), principal.SubjectID)
	require.Equal(t, "tenant-b", principal.TenantID)
	require.True(t, principal.HasPermission("api:user:manage"))
	require.Equal(t, []string{"admin"}, iamauth.Roles(bound))
	require.Equal(t, "platform", iamauth.ActiveScopeType(bound))
	require.NotNil(t, iamauth.PermissionSet(bound))
	require.True(t, HasPermission(bound, "api:user:manage"))
	require.True(t, HasPermission(bound, "api:any:thing"))
}
