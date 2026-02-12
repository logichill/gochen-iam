package middleware

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/auth"
	"gochen/errorx"
	hbasic "gochen/httpx/nethttp"
)

func TestParseToken_ValidJWT(t *testing.T) {
	secretKey := "test-secret-key"
	userID := int64(123)
	username := "testuser"
	roles := []string{"user", "admin"}
	permissions := []string{"read", "write"}

	// 生成有效 token
	token, err := GenerateToken(userID, username, roles, permissions, secretKey)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// 解析 token
	claims, err := ParseToken(token, secretKey)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected UserID %d, got %d", userID, claims.UserID)
	}
	if claims.Username != username {
		t.Errorf("expected Username %s, got %s", username, claims.Username)
	}
	if len(claims.Roles) != len(roles) {
		t.Errorf("expected %d roles, got %d", len(roles), len(claims.Roles))
	}
	if len(claims.Permissions) != len(permissions) {
		t.Errorf("expected %d permissions, got %d", len(permissions), len(claims.Permissions))
	}
}

func TestParseToken_InvalidJWT(t *testing.T) {
	secretKey := "test-secret-key"

	// 使用无效 token
	_, err := ParseToken("invalid-token", secretKey)
	if err == nil {
		t.Error("expected error for invalid token, got nil")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	secretKey := "test-secret-key"
	wrongKey := "wrong-secret-key"

	token, err := GenerateToken(1, "user", nil, nil, secretKey)
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

	// 创建过期的 token
	claims := &JWTClaims{
		UserID:   1,
		Username: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // 1小时前过期
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
			defer func() {
				os.Unsetenv("APP_ENV")
			}()

			result := isDevEnv()
			if result != tt.expected {
				t.Errorf("isDevEnv() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateAuthConfig_Production_NoSecret(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	os.Unsetenv("AUTH_SECRET")
	defer func() {
		os.Unsetenv("APP_ENV")
	}()

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
	err := ValidateAuthConfig(config)
	if err != nil {
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
	_, err := GenerateToken(1, "user", nil, nil, "")
	if err == nil {
		t.Error("expected error for empty secret, got nil")
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
	ctx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithRoles(ctx, []string{"user"})

	if !HasAnyRole(ctx, "user") {
		t.Error("expected HasAnyRole(user)=true")
	}
	if HasAnyRole(ctx, "admin") {
		t.Error("expected HasAnyRole(admin)=false")
	}
	if !HasAnyRole(ctx) {
		t.Error("expected HasAnyRole()=true when no role required")
	}
}

func TestRequireAnyRole(t *testing.T) {
	ctx, err := hbasic.NewRequestContext(context.Background())
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

func TestHasPermission_AdminRoleOverrides(t *testing.T) {
	ctx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithRoles(ctx, []string{"system_admin"})

	if !HasPermission(ctx, "any:permission") {
		t.Error("expected admin to have all permissions")
	}
}

func TestRequirePermission(t *testing.T) {
	ctx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithPermissions(ctx, []string{"a:read"})

	if err := RequirePermission(ctx, "a:write"); err == nil {
		t.Error("expected RequirePermission(a:write) to fail")
	}
	if err := RequirePermission(ctx, "a:read"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 空权限视为不需要校验
	if err := RequirePermission(ctx, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequirePermission_ReturnsForbidden(t *testing.T) {
	ctx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	ctx = auth.WithPermissions(ctx, []string{"a:read"})

	err = RequirePermission(ctx, "a:write")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errorx.Is(err, errorx.Forbidden) {
		t.Fatalf("expected Forbidden, got: %v", err)
	}
}

func TestRequiredPermissionsRegistry(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	_ = PermissionMiddleware("a:read")
	_ = PermissionMiddleware("a:read")
	_ = PermissionMiddleware("b:write")
	_ = PermissionMiddleware("invalid-perm")

	perms := RequiredPermissions()
	if len(perms) != 2 {
		t.Fatalf("expected 2 unique permissions, got %d: %#v", len(perms), perms)
	}
	if perms[0] != "a:read" || perms[1] != "b:write" {
		t.Fatalf("unexpected permissions: %#v", perms)
	}
}

func TestPermissionMiddleware_InvalidPermission_NotRegistered(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	_ = PermissionMiddleware("task:read")
	_ = PermissionMiddleware("task:read-self")
	_ = PermissionMiddleware("")

	perms := RequiredPermissions()
	if len(perms) != 1 || perms[0] != "task:read" {
		t.Fatalf("unexpected permissions: %#v", perms)
	}
}

func TestValidateStrictPermissionRegistry_StrictEmpty(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	if err := ValidateStrictPermissionRegistry(); err == nil {
		t.Fatalf("expected error when strict enabled and registry empty")
	}
}

func TestValidateStrictPermissionRegistry_StrictNonEmpty(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	_ = PermissionMiddleware("task:read")
	if err := ValidateStrictPermissionRegistry(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
