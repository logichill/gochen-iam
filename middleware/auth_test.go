package middleware

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/authctx"
	hbasic "gochen/httpx/nethttp"
	"gochen/runtime/errorx"
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

func TestParseToken_TestToken_Allowed(t *testing.T) {
	// 设置环境变量允许测试令牌
	os.Setenv("GO_ENV", "testing")
	os.Setenv("ALLOW_TEST_TOKEN", "true")
	defer func() {
		os.Unsetenv("GO_ENV")
		os.Unsetenv("ALLOW_TEST_TOKEN")
	}()

	claims, err := ParseToken("test-token", "any-secret")
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("expected UserID 1, got %d", claims.UserID)
	}
	if claims.Username != "admin" {
		t.Errorf("expected Username admin, got %s", claims.Username)
	}
}

func TestParseToken_TestToken_NotAllowed(t *testing.T) {
	// 确保环境变量未设置
	os.Unsetenv("ALLOW_TEST_TOKEN")

	_, err := ParseToken("test-token", "any-secret")
	if err == nil {
		t.Error("expected error when test token is not allowed, got nil")
	}
}

func TestIsTestTokenAllowed(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"empty", "", false},
		{"true", "true", true},
		{"1", "1", true},
		{"false", "false", false},
		{"0", "0", false},
		{"random", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("GO_ENV", "testing")
			defer os.Unsetenv("GO_ENV")
			if tt.envValue == "" {
				os.Unsetenv("ALLOW_TEST_TOKEN")
			} else {
				os.Setenv("ALLOW_TEST_TOKEN", tt.envValue)
			}
			defer os.Unsetenv("ALLOW_TEST_TOKEN")

			result := isTestTokenAllowed()
			if result != tt.expected {
				t.Errorf("isTestTokenAllowed() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsDevEnv(t *testing.T) {
	tests := []struct {
		name     string
		goEnv    string
		appEnv   string
		expected bool
	}{
		{"empty", "", "", false},
		{"go_env_development", "development", "", true},
		{"go_env_dev", "dev", "", true},
		{"go_env_test", "test", "", true},
		{"go_env_testing", "testing", "", true},
		{"app_env_development", "", "development", true},
		{"app_env_dev", "", "dev", true},
		{"app_env_test", "", "test", true},
		{"app_env_testing", "", "testing", true},
		{"production", "production", "", false},
		{"prod", "prod", "", false},
		{"go_env_takes_precedence", "development", "production", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("GO_ENV")
			os.Unsetenv("APP_ENV")
			if tt.goEnv != "" {
				os.Setenv("GO_ENV", tt.goEnv)
			}
			if tt.appEnv != "" {
				os.Setenv("APP_ENV", tt.appEnv)
			}
			defer func() {
				os.Unsetenv("GO_ENV")
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
	os.Setenv("GO_ENV", "production")
	os.Unsetenv("AUTH_SECRET")
	defer func() {
		os.Unsetenv("GO_ENV")
	}()

	config := &AuthConfig{SecretKey: ""}
	err := ValidateAuthConfig(config)
	if err == nil {
		t.Error("expected error in production without AUTH_SECRET, got nil")
	}
}

func TestValidateAuthConfig_Production_WithSecret(t *testing.T) {
	os.Setenv("GO_ENV", "production")
	defer os.Unsetenv("GO_ENV")

	config := &AuthConfig{SecretKey: "my-secret-key"}
	err := ValidateAuthConfig(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateAuthConfig_Production_TestTokenEnabled(t *testing.T) {
	os.Setenv("GO_ENV", "production")
	os.Setenv("ALLOW_TEST_TOKEN", "true")
	defer func() {
		os.Unsetenv("GO_ENV")
		os.Unsetenv("ALLOW_TEST_TOKEN")
	}()

	config := &AuthConfig{SecretKey: "my-secret-key"}
	err := ValidateAuthConfig(config)
	if err == nil {
		t.Error("expected error in production when ALLOW_TEST_TOKEN is enabled, got nil")
	}
}

func TestValidateAuthConfig_Development_NoSecret(t *testing.T) {
	os.Setenv("GO_ENV", "development")
	defer os.Unsetenv("GO_ENV")

	config := &AuthConfig{SecretKey: ""}
	err := ValidateAuthConfig(config)
	if err != nil {
		t.Errorf("unexpected error in development: %v", err)
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
	os.Setenv("GO_ENV", "testing")
	defer os.Unsetenv("GO_ENV")

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

func TestDefaultAuthConfig_Development(t *testing.T) {
	os.Unsetenv("AUTH_SECRET")
	os.Setenv("GO_ENV", "development")
	defer os.Unsetenv("GO_ENV")

	config := DefaultAuthConfig()
	if config.SecretKey == "" {
		t.Error("expected default secret key in development, got empty")
	}
	if config.SecretKey != "your-secret-key" {
		t.Errorf("expected default secret key 'your-secret-key', got '%s'", config.SecretKey)
	}
}

func TestDefaultAuthConfig_Production_NoSecret(t *testing.T) {
	os.Unsetenv("AUTH_SECRET")
	os.Setenv("GO_ENV", "production")
	defer os.Unsetenv("GO_ENV")

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
	ctx := hbasic.NewRequestContext(context.Background())
	ctx = authctx.WithRoles(ctx, []string{"user"})

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
	ctx := hbasic.NewRequestContext(context.Background())
	ctx = authctx.WithRoles(ctx, []string{"user"})

	if err := RequireAnyRole(ctx, "admin"); err == nil {
		t.Error("expected RequireAnyRole(admin) to fail")
	}
	if err := RequireAnyRole(ctx, "user"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHasPermission_AdminRoleOverrides(t *testing.T) {
	ctx := hbasic.NewRequestContext(context.Background())
	ctx = authctx.WithRoles(ctx, []string{"system_admin"})

	if !HasPermission(ctx, "any:permission") {
		t.Error("expected admin to have all permissions")
	}
}

func TestRequirePermission(t *testing.T) {
	ctx := hbasic.NewRequestContext(context.Background())
	ctx = authctx.WithPermissions(ctx, []string{"a:read"})

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
	ctx := hbasic.NewRequestContext(context.Background())
	ctx = authctx.WithPermissions(ctx, []string{"a:read"})

	err := RequirePermission(ctx, "a:write")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errorx.IsErrorCode(err, errorx.Forbidden) {
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

func TestValidateStrictPermissionRegistryLoaded_StrictEmpty(t *testing.T) {
	os.Setenv("AUTH_STRICT_PERMISSION_REGISTRY", "true")
	defer os.Unsetenv("AUTH_STRICT_PERMISSION_REGISTRY")

	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	if err := ValidateStrictPermissionRegistryLoaded(); err == nil {
		t.Fatalf("expected error when strict enabled and registry empty")
	}
}

func TestValidateStrictPermissionRegistryLoaded_StrictNonEmpty(t *testing.T) {
	os.Setenv("AUTH_STRICT_PERMISSION_REGISTRY", "true")
	defer os.Unsetenv("AUTH_STRICT_PERMISSION_REGISTRY")

	resetRequiredPermissionsRegistryForTest()
	defer resetRequiredPermissionsRegistryForTest()

	_ = PermissionMiddleware("task:read")
	if err := ValidateStrictPermissionRegistryLoaded(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
