package middleware

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen/errors"
)

// signLegacyAccessToken 按 a012f56 之前的签发形态手工构造 legacy access token：
// 无 token_type，claims 仅含 user_id/active_scope_id/binding_version/permissions。
// legacyJTI 为空表示完全旧版形态（无 JTI，永远无法进入吊销名单）。
func signLegacyAccessToken(t *testing.T, secretKey, legacyJTI string) string {
	t.Helper()
	now := time.Now()
	claims := &JWTClaims{
		UserID:         7,
		ActiveScopeID:  11,
		BindingVersion: "legacy-binding",
		Permissions:    []string{"user:api:read"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        legacyJTI,
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("sign legacy access token: %v", err)
	}
	return signed
}

// TestLegacyAccessTokenWithoutJTIRejectedAsUnrevocable 锁定缺陷 R3c-F01 的修复：
// 无 JTI 的 legacy 形态 access token 曾被接受，但 claims.ID 为空、无法写入以 JTI 为键的
// 吊销存储，形成"可通过校验却不可吊销"的缺口。修复后该形态必须在解析与中间件两处被拒。
func TestLegacyAccessTokenWithoutJTIRejectedAsUnrevocable(t *testing.T) {
	const secretKey = "test-secret-key"
	token := signLegacyAccessToken(t, secretKey, "")

	if _, err := ParseToken(token, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("legacy access token without jti must be rejected by ParseToken, got %v", err)
	}

	cfg := &AuthConfig{
		Environment:       "test",
		SecretKey:         secretKey,
		RevokedTokenStore: NewMemoryRevokedTokenStore(),
	}
	if _, err := ValidateAccessToken(t.Context(), token, cfg); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("legacy access token without jti must be rejected by ValidateAccessToken, got %v", err)
	}

	// 端到端：AuthMiddleware 不得把该形态 token 放行到 handler。
	resetRequiredPermissionsRegistryForTest()
	t.Cleanup(resetRequiredPermissionsRegistryForTest)
	RegisterRequiredPermissions("iam:api:test")
	mw := AuthMiddleware(&AuthConfig{
		Environment: "test",
		SecretKey:   secretKey,
		TokenHeader: "Authorization",
		TokenPrefix: "Bearer ",
	})
	ctx := newTestHTTPContext(t, "GET", "/api/v1/users", map[string]string{"Authorization": "Bearer " + token})
	called := false
	if err := mw(ctx, func() error { called = true; return nil }); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("AuthMiddleware must reject legacy token without jti, got %v", err)
	}
	if called {
		t.Fatal("handler must not be reached by an unrevocable legacy token")
	}
}

// TestLegacyAccessTokenWithBlankJTIRejectedAsUnrevocable 验证空白 JTI 与吊销存储的
// TrimSpace 语义对齐：空白 JTI 同样无法写入吊销名单，因此必须视为缺失并拒绝。
func TestLegacyAccessTokenWithBlankJTIRejectedAsUnrevocable(t *testing.T) {
	const secretKey = "test-secret-key"
	token := signLegacyAccessToken(t, secretKey, "   ")

	if _, err := ParseToken(token, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("legacy access token with blank jti must be rejected, got %v", err)
	}
}

// TestLegacyFormAccessTokenWithJTIRemainsAcceptedAndRevocable 锁定兼容窗口的其余部分：
// 携带非空 JTI 的 legacy 形态 token 仍被接受，且吊销语义完整可断言（修复前该形态以外
// 的 legacy token 不可吊销，这是本用例与上一个用例共同划出的新边界）。
func TestLegacyFormAccessTokenWithJTIRemainsAcceptedAndRevocable(t *testing.T) {
	const secretKey = "test-secret-key"
	token := signLegacyAccessToken(t, secretKey, "legacy-form-jti-1")

	claims, err := ParseToken(token, secretKey)
	if err != nil {
		t.Fatalf("legacy-form token with jti must stay accepted, got %v", err)
	}
	if claims.TokenType != "" {
		t.Fatalf("expected legacy form (empty token_type), got %q", claims.TokenType)
	}
	if strings.TrimSpace(claims.ID) != "legacy-form-jti-1" {
		t.Fatalf("expected jti preserved, got %q", claims.ID)
	}

	cfg := &AuthConfig{
		Environment:       "test",
		SecretKey:         secretKey,
		RevokedTokenStore: NewMemoryRevokedTokenStore(),
	}
	if _, err := ValidateAccessToken(t.Context(), token, cfg); err != nil {
		t.Fatalf("legacy-form token with jti must pass validation, got %v", err)
	}

	if err := RevokeAccessTokenJTI(t.Context(), cfg, claims.ID, claims.ExpiresAt.Time); err != nil {
		t.Fatalf("revoke legacy-form token jti: %v", err)
	}
	if _, err := ValidateAccessToken(t.Context(), token, cfg); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("revoked legacy-form token must be rejected, got %v", err)
	}
}
