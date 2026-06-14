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

func TestIsDevEnv(t *testing.T) {
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
			os.Unsetenv("APP_ENV")
			if tt.appEnv != "" {
				os.Setenv("APP_ENV", tt.appEnv)
			}
			defer func() { os.Unsetenv("APP_ENV") }()

			if result := isDevEnv(); result != tt.expected {
				t.Errorf("isDevEnv() = %v, expected %v", result, tt.expected)
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

	config := &AuthConfig{SecretKey: "my-secret-key"}
	if err := ValidateAuthConfig(config); err != nil {
		t.Errorf("unexpected error: %v", err)
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
			tenantID, err := tenant.ResolveRequestTenantID(tt.requestTenant, tt.currentTenant, tt.requireTenant)
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

func TestDefaultAuthConfig_Development_NoSecret(t *testing.T) {
	os.Unsetenv("AUTH_SECRET")
	os.Setenv("APP_ENV", "development")
	defer os.Unsetenv("APP_ENV")

	config := DefaultAuthConfig()
	if config.SecretKey != "" {
		t.Errorf("expected empty secret key in development without AUTH_SECRET, got '%s'", config.SecretKey)
	}
}

func TestDefaultAuthConfig_Production_NoSecret(t *testing.T) {
	os.Unsetenv("AUTH_SECRET")
	os.Setenv("APP_ENV", "production")
	defer os.Unsetenv("APP_ENV")

	config := DefaultAuthConfig()
	if config.SecretKey != "" {
		t.Errorf("expected empty secret key in production without AUTH_SECRET, got '%s'", config.SecretKey)
	}
}

func TestDefaultAuthConfig_WithEnvSecret(t *testing.T) {
	os.Setenv("AUTH_SECRET", "env-secret-key")
	defer os.Unsetenv("AUTH_SECRET")

	config := DefaultAuthConfig()
	if config.SecretKey != "env-secret-key" {
		t.Errorf("expected secret from env 'env-secret-key', got '%s'", config.SecretKey)
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

func TestHasPermission_WildcardPermissions(t *testing.T) {
	ctx, err := httpx.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithPermissions(ctx, []string{"api:*:*", "menu:*:view"})

	if !HasPermission(ctx, "api:any:permission") {
		t.Error("expected api:*:* to match api:any:permission")
	}
	if !HasPermission(ctx, "menu:dashboard.home:view") {
		t.Error("expected menu:*:view to match menu:dashboard.home:view")
	}
	if HasPermission(ctx, "action:mcp:invoke") {
		t.Error("expected missing action permission")
	}
}
