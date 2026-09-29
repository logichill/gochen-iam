package middleware

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/auth"
	"gochen-iam/tenant"
	"gochen/errors"
	"gochen/httpx"
)

func TestParseToken_ValidJWT(t *testing.T) {
	secretKey := "test-secret-key"
	userID := int64(123)
	activeScopeID := int64(88)
	bindingVersion := "binding-v1"
	permissions := []string{"read", "write"}

	token, err := GenerateToken(userID, activeScopeID, bindingVersion, permissions, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := ParseToken(token, secretKey)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected UserID %d, got %d", userID, claims.UserID)
	}
	if claims.ActiveScopeID != activeScopeID {
		t.Errorf("expected ActiveScopeID %d, got %d", activeScopeID, claims.ActiveScopeID)
	}
	if claims.BindingVersion != bindingVersion {
		t.Errorf("expected BindingVersion %s, got %s", bindingVersion, claims.BindingVersion)
	}
	if len(claims.Permissions) != len(permissions) {
		t.Errorf("expected %d permissions, got %d", len(permissions), len(claims.Permissions))
	}
}

func TestParseToken_InvalidJWT(t *testing.T) {
	secretKey := "test-secret-key"
	_, err := ParseToken("invalid-token", secretKey)
	if err == nil {
		t.Error("expected error for invalid token, got nil")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	secretKey := "test-secret-key"
	wrongKey := "wrong-secret-key"

	token, err := GenerateToken(1, 99, "binding-v1", nil, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	_, err = ParseToken(token, wrongKey)
	if err == nil {
		t.Error("expected error for wrong secret key, got nil")
	}
}

func TestParseToken_ExpiredJWT(t *testing.T) {
	secretKey := "test-secret-key"

	claims := &JWTClaims{
		UserID:        1,
		ActiveScopeID: 7,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(secretKey))

	_, err := ParseToken(signed, secretKey)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestGenerateAndParseActivationToken(t *testing.T) {
	secretKey := "test-secret-key"
	token, err := GenerateActivationToken(7, "binding-v1", []int64{11, 22}, secretKey, time.Minute)
	if err != nil {
		t.Fatalf("GenerateActivationToken: %v", err)
	}
	claims, err := ParseActivationToken(token, secretKey)
	if err != nil {
		t.Fatalf("ParseActivationToken: %v", err)
	}
	if claims.UserID != 7 {
		t.Fatalf("expected user 7, got %d", claims.UserID)
	}
	if claims.BindingVersion != "binding-v1" {
		t.Fatalf("expected binding-v1, got %s", claims.BindingVersion)
	}
	if len(claims.AvailableScopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(claims.AvailableScopes))
	}
}

func TestAccessAndActivationTokensAreNotInterchangeable(t *testing.T) {
	const secretKey = "test-secret-key"
	activationToken, err := GenerateActivationToken(7, "binding-v1", []int64{11}, secretKey, time.Minute)
	if err != nil {
		t.Fatalf("GenerateActivationToken: %v", err)
	}
	if _, err := ParseToken(activationToken, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("activation token parsed as access token: %v", err)
	}

	accessToken, err := GenerateToken(7, 11, "binding-v1", nil, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := ParseActivationToken(accessToken, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("access token parsed as activation token: %v", err)
	}
}

func TestLegacyTokensWithoutTypeRemainPurposeBound(t *testing.T) {
	const secretKey = "test-secret-key"
	now := time.Now()
	legacyAccess := jwt.NewWithClaims(jwt.SigningMethodHS256, &JWTClaims{
		UserID:        7,
		ActiveScopeID: 11,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	legacyAccessToken, err := legacyAccess.SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("sign legacy access token: %v", err)
	}
	if _, err := ParseToken(legacyAccessToken, secretKey); err != nil {
		t.Fatalf("parse legacy access token: %v", err)
	}
	if _, err := ParseActivationToken(legacyAccessToken, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("legacy access token parsed as activation token: %v", err)
	}

	legacyActivation := jwt.NewWithClaims(jwt.SigningMethodHS256, &ActivationClaims{
		UserID:          7,
		AvailableScopes: []int64{11},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	legacyActivationToken, err := legacyActivation.SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("sign legacy activation token: %v", err)
	}
	if _, err := ParseActivationToken(legacyActivationToken, secretKey); err != nil {
		t.Fatalf("parse legacy activation token: %v", err)
	}
	if _, err := ParseToken(legacyActivationToken, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("legacy activation token parsed as access token: %v", err)
	}
}

func TestTokensWithUnknownExplicitTypeAreRejected(t *testing.T) {
	const secretKey = "test-secret-key"
	claims := &JWTClaims{
		TokenType:     "unknown",
		UserID:        7,
		ActiveScopeID: 11,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secretKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	if _, err := ParseToken(signed, secretKey); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("unknown explicit token type should be rejected, got %v", err)
	}
}

func TestValidateAccessTokenRequiresActiveScope(t *testing.T) {
	token, err := GenerateToken(7, 0, "binding-v1", nil, "test-secret-key")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := ValidateAccessToken(t.Context(), token, &AuthConfig{SecretKey: "test-secret-key"}); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("zero-scope access token should be rejected, got %v", err)
	}
}

func TestParseTokenRejectsNonHS256HMAC(t *testing.T) {
	claims := &JWTClaims{
		TokenType:     tokenTypeAccess,
		UserID:        7,
		ActiveScopeID: 11,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := token.SignedString([]byte("test-secret-key"))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	if _, err := ParseToken(signed, "test-secret-key"); !errors.Is(err, errors.Unauthorized) {
		t.Fatalf("HS512 token should be rejected, got %v", err)
	}
}

func TestIsDevEnvironment(t *testing.T) {
	tests := []struct {
		name     string
		appEnv   string
		expected bool
	}{
		{"empty", "", false},
		{"app_env_development", "development", true},
		{"app_env_dev", "dev", true},
		{"app_env_test", "test", true},
		{"app_env_testing", "testing", true},
		{"production", "production", false},
		{"prod", "prod", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := isDevEnvironment(tt.appEnv); result != tt.expected {
				t.Errorf("isDevEnvironment(tt.appEnv) = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateAuthConfig_Production_NoSecret(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	os.Unsetenv("AUTH_SECRET")
	defer func() { os.Unsetenv("APP_ENV") }()

	config := &AuthConfig{SecretKey: ""}
	err := ValidateAuthConfig(config)
	if err == nil {
		t.Error("expected error in production without AUTH_SECRET, got nil")
	}
}

func TestValidateAuthConfig_Production_WithSecret(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	defer os.Unsetenv("APP_ENV")

	config := &AuthConfig{SecretKey: "my-secret-key", RevokedTokenStore: persistentRevokedTokenStoreStub{}}
	if err := ValidateAuthConfig(config); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateAuthConfig_ProductionRejectsMemoryRevokedTokenStore(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	config := &AuthConfig{SecretKey: "my-secret-key", RevokedTokenStore: newMemoryRevokedTokenStore()}
	if err := ValidateAuthConfig(config); err == nil {
		t.Fatal("expected production config to reject memory revoked token store")
	}
}

func TestExplicitAuthEnvironmentDoesNotReadProcessEnvironment(t *testing.T) {
	for _, environment := range []string{"", "   ", "production", "test"} {
		t.Run("environment="+environment, func(t *testing.T) {
			cfg := DefaultAuthConfigForEnvironment(environment)
			cfg.SecretKey = "test-secret"
			cfg.RevokedTokenStore = newMemoryRevokedTokenStore()
			for _, processEnvironment := range []string{"test", "production"} {
				t.Setenv("APP_ENV", processEnvironment)
				wantDev := environment == "test"
				if err := ValidateAuthConfig(cfg); (err == nil) != wantDev {
					t.Fatalf("APP_ENV=%s: memory store validation = %v", processEnvironment, err)
				}
				cfg.RevokedTokenStore = persistentRevokedTokenStoreStub{}
				cfg.AllowQueryToken = true
				if err := ValidateAuthConfig(cfg); (err == nil) != wantDev {
					t.Fatalf("APP_ENV=%s: query token validation = %v", processEnvironment, err)
				}
				if cookieSecure(cfg) == wantDev {
					t.Fatalf("APP_ENV=%s: unexpected Secure cookie policy", processEnvironment)
				}
				cfg.AllowQueryToken = false
				cfg.RevokedTokenStore = newMemoryRevokedTokenStore()
			}
		})
	}
}

func TestValidateAuthConfig_Development_NoSecret(t *testing.T) {
	os.Setenv("APP_ENV", "development")
	defer os.Unsetenv("APP_ENV")

	config := &AuthConfig{SecretKey: ""}
	err := ValidateAuthConfig(config)
	if err == nil {
		t.Error("expected error in development without AUTH_SECRET, got nil")
	}
}

func TestExtractToken_FromQuery_DisabledByDefault(t *testing.T) {
	cfg := &AuthConfig{TokenHeader: "Authorization", TokenPrefix: "Bearer "}
	if got := extractTokenFromHeadersAndQuery(nil, func(key string) string {
		if key == "token" {
			return "q-token"
		}
		return ""
	}, cfg); got != "" {
		t.Fatalf("expected query token disabled by default, got %q", got)
	}
}

func TestExtractToken_FromQuery_AllowedInDev(t *testing.T) {
	os.Setenv("APP_ENV", "testing")
	defer os.Unsetenv("APP_ENV")

	cfg := &AuthConfig{TokenHeader: "Authorization", TokenPrefix: "Bearer ", AllowQueryToken: true}
	if got := extractTokenFromHeadersAndQuery(nil, func(key string) string {
		if key == "token" {
			return "q-token"
		}
		return ""
	}, cfg); got != "q-token" {
		t.Fatalf("expected token from query, got %q", got)
	}
}

func TestGenerateToken_EmptySecret(t *testing.T) {
	_, err := GenerateToken(1, 99, "binding-v1", nil, "")
	if err == nil {
		t.Error("expected error for empty secret, got nil")
	}
}

func TestRefreshToken_PreservesBindingClaims(t *testing.T) {
	secretKey := "test-secret-key"

	token, err := GenerateToken(1, 42, "binding-v1", []string{"read"}, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	refreshed, err := RefreshToken(token, secretKey)
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}

	claims, err := ParseToken(refreshed, secretKey)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}
	if claims.ActiveScopeID != 42 {
		t.Fatalf("expected active scope 42, got %d", claims.ActiveScopeID)
	}
	if claims.BindingVersion != "binding-v1" {
		t.Fatalf("expected binding-v1, got %s", claims.BindingVersion)
	}
}

func TestResolveRequestTenantID(t *testing.T) {
	t.Setenv("IAM_TENANT_MODE", "tenant")

	tests := []struct {
		name          string
		requestTenant string
		currentTenant string
		requireTenant bool
		wantTenant    string
		wantCode      errors.ErrorCode
	}{
		{name: "request wins when current empty", requestTenant: "tenant-a", wantTenant: "tenant-a"},
		{name: "current fills missing request", currentTenant: "tenant-a", wantTenant: "tenant-a"},
		{name: "matching tenants", requestTenant: "tenant-a", currentTenant: "tenant-a", wantTenant: "tenant-a"},
		{name: "request overrides current", requestTenant: "tenant-a", currentTenant: "tenant-b", wantTenant: "tenant-a"},
		{name: "required tenant missing", requireTenant: true, wantCode: errors.Validation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID, err := tenant.ResolveRequestTenantIDWithPolicy(tenant.Policy{Mode: tenant.ModeTenant}, tt.requestTenant, tt.currentTenant, tt.requireTenant)
			if tt.wantCode != "" {
				if !errors.Is(err, tt.wantCode) {
					t.Fatalf("expected %s, got %v", tt.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTenantID failed: %v", err)
			}
			if tenantID != tt.wantTenant {
				t.Fatalf("expected tenant %s, got %s", tt.wantTenant, tenantID)
			}
		})
	}
}

func TestDefaultAuthConfigForEnvironmentIgnoresProcessEnvironment(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_SECRET", "environment-secret")
	t.Setenv("AUTH_ALLOW_QUERY_TOKEN", "true")
	t.Setenv("AUTH_ACCESS_TOKEN_TTL", "1m")
	t.Setenv("IAM_TENANT_MODE", "tenant")
	config := DefaultAuthConfigForEnvironment("production")
	if config.Environment != "production" || config.SecretKey != "" || config.AllowQueryToken ||
		config.AccessTokenTTL != defaultAccessTokenTTL || config.TenantPolicy.Mode != tenant.ModeSingle {
		t.Fatal("default config unexpectedly read process environment")
	}
}

func TestAuthEntryPointsRejectMissingConfig(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("AUTH_SECRET", "environment-secret")
	if err := ValidateAuthConfig(nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("ValidateAuthConfig(nil) = %v", err)
	}
	for _, middleware := range []httpx.Middleware{AuthMiddleware(nil), OptionalAuthMiddleware(nil)} {
		called := false
		err := middleware(newTestHTTPContext(t, "GET", "/api/v1/users"), func() error { called = true; return nil })
		if !errors.Is(err, errors.InvalidInput) || called {
			t.Fatalf("missing config: err=%v next=%v", err, called)
		}
	}
	if _, err := ValidateAccessToken(context.Background(), "token", nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("ValidateAccessToken(nil config) = %v", err)
	}
}

func TestHasAnyRole(t *testing.T) {
	ctx, err := httpx.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithRoles(ctx, []string{" user "})

	if !HasAnyRole(ctx, "user") {
		t.Error("expected HasAnyRole(user)=true")
	}
	if !HasAnyRole(ctx, " user ") {
		t.Error("expected HasAnyRole to trim required roles")
	}
	if HasAnyRole(ctx, "admin") {
		t.Error("expected HasAnyRole(admin)=false")
	}
	if HasAnyRole(ctx, "   ") {
		t.Error("expected blank required role to be ignored and fail closed")
	}
	if HasAnyRole(nil, "user") {
		t.Error("expected nil ctx to fail closed")
	}
	if !HasAnyRole(ctx) {
		t.Error("expected HasAnyRole()=true when no role required")
	}
}

func TestRequireAnyRole(t *testing.T) {
	ctx, err := httpx.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithRoles(ctx, []string{"user"})

	if err := RequireAnyRole(ctx, "admin"); err == nil {
		t.Error("expected RequireAnyRole(admin) to fail")
	}
	if err := RequireAnyRole(ctx, "user"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type persistentRevokedTokenStoreStub struct{}

func (persistentRevokedTokenStoreStub) Consume(context.Context, string, time.Time) (bool, error) {
	return true, nil
}
func (persistentRevokedTokenStoreStub) IsRevoked(context.Context, string) (bool, error) {
	return false, nil
}

func TestHasPermission_WildcardPermissions(t *testing.T) {
	ctx, err := httpx.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithPermissions(ctx, []string{"*:api:*", "*:menu:view"})

	if !HasPermission(ctx, "any:api:permission") {
		t.Error("expected *:api:* to match any:api:permission")
	}
	if !HasPermission(ctx, "dashboard.home:menu:view") {
		t.Error("expected *:menu:view to match dashboard.home:menu:view")
	}
	if HasPermission(ctx, "mcp:action:invoke") {
		t.Error("expected missing action permission")
	}

}
