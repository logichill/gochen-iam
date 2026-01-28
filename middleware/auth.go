package middleware

import (
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/auth"
	httpx "gochen/httpx"
	hbasic "gochen/httpx/nethttp"
	"gochen/runtime/errorx"
)

const (
	envAccessTokenTTL      = "AUTH_ACCESS_TOKEN_TTL"
	envAllowQueryToken     = "AUTH_ALLOW_QUERY_TOKEN"
	envRequireTenant       = "AUTH_REQUIRE_TENANT"
	envAllowTenantQuery    = "AUTH_ALLOW_TENANT_QUERY"
	envTenantHeader        = "AUTH_TENANT_HEADER"
	defaultAccessTokenTTL  = 24 * time.Hour
	defaultTenantHeaderKey = httpx.HeaderTenantID
)

// AuthConfig 认证配置
type AuthConfig struct {
	SecretKey    string   `json:"secret_key" yaml:"secret_key"`
	TokenHeader  string   `json:"token_header" yaml:"token_header"`
	TokenPrefix  string   `json:"token_prefix" yaml:"token_prefix"`
	SkipPaths    []string `json:"skip_paths" yaml:"skip_paths"`
	RequiredRole string   `json:"required_role" yaml:"required_role"`

	AccessTokenTTL   time.Duration `json:"-" yaml:"-"`
	AllowQueryToken  bool          `json:"-" yaml:"-"`
	RequireTenant    bool          `json:"-" yaml:"-"`
	AllowTenantQuery bool          `json:"-" yaml:"-"`
	TenantHeader     string        `json:"-" yaml:"-"`
}

// DefaultAuthConfig 默认认证配置
// 生产环境必须设置 AUTH_SECRET 环境变量
func DefaultAuthConfig() *AuthConfig {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		// 仅在开发/测试环境允许使用默认密钥
		if isDevEnv() {
			secret = "your-secret-key"
		} else {
			// 生产环境不提供默认值，强制要求配置
			// 调用方应在启动时检查并处理此情况
			secret = ""
		}
	}

	ttl := defaultAccessTokenTTL
	if v := os.Getenv(envAccessTokenTTL); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			ttl = d
		}
	}

	tenantHeader := os.Getenv(envTenantHeader)
	if tenantHeader == "" {
		tenantHeader = defaultTenantHeaderKey
	}

	return &AuthConfig{
		SecretKey:        secret,
		TokenHeader:      "Authorization",
		TokenPrefix:      "Bearer ",
		AccessTokenTTL:   ttl,
		AllowQueryToken:  (os.Getenv(envAllowQueryToken) == "true" || os.Getenv(envAllowQueryToken) == "1") && isDevEnv(),
		RequireTenant:    os.Getenv(envRequireTenant) == "true" || os.Getenv(envRequireTenant) == "1",
		AllowTenantQuery: os.Getenv(envAllowTenantQuery) == "true" || os.Getenv(envAllowTenantQuery) == "1",
		TenantHeader:     tenantHeader,
		SkipPaths: []string{
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/health",
			"/api/v1/ping",
		},
	}
}

// isDevEnv 检查是否为开发/测试环境
// 通过 GO_ENV 或 APP_ENV 环境变量判断（GO_ENV 优先）
func isDevEnv() bool {
	env := os.Getenv("GO_ENV")
	if env == "" {
		env = os.Getenv("APP_ENV")
	}
	return env == "development" || env == "dev" || env == "test" || env == "testing"
}

// IsDevEnv 对外暴露统一的 dev/test 环境判定（兼容 GO_ENV/APP_ENV）。
func IsDevEnv() bool { return isDevEnv() }

// ValidateAuthConfig 验证认证配置是否完整
// 应在应用启动时调用，生产环境缺少必要配置时返回错误
func ValidateAuthConfig(config *AuthConfig) error {
	if config == nil {
		config = DefaultAuthConfig()
	}
	if config.SecretKey == "" {
		if !isDevEnv() {
			return errorx.NewError(errorx.Internal, "生产环境必须设置 AUTH_SECRET 环境变量")
		}
	}
	// 生产环境禁止启用测试令牌，避免固定口令拿到高权限。
	if !isDevEnv() && (os.Getenv("ALLOW_TEST_TOKEN") == "true" || os.Getenv("ALLOW_TEST_TOKEN") == "1") {
		return errorx.NewError(errorx.Internal, "生产环境禁止启用 ALLOW_TEST_TOKEN")
	}
	// 生产环境禁止允许 query token，避免 token 泄露到 URL/日志链路。
	if !isDevEnv() && config.AllowQueryToken {
		return errorx.NewError(errorx.Internal, "生产环境禁止启用 AUTH_ALLOW_QUERY_TOKEN")
	}
	return nil
}

// AuthMiddleware 认证中间件
//
// 设计目标：
//   - 解析 Token 获取 user_id / roles / permissions；
//   - 将身份与权限信息注入 IRequestContext，供后续基于请求上下文的 RBAC 辅助函数使用。
func AuthMiddleware(config *AuthConfig) httpx.Middleware {
	if config == nil {
		config = DefaultAuthConfig()
	}

	return func(ctx httpx.IContext, next func() error) error {
		// 检查是否需要跳过认证
		path := ctx.GetPath()
		for _, skipPath := range config.SkipPaths {
			if strings.HasPrefix(path, skipPath) {
				return next()
			}
		}

		// 获取 token（必需鉴权：无 token 直接拒绝；如需可选鉴权请使用 OptionalAuthMiddleware）
		token := extractToken(ctx, config)
		if token == "" {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "用户未认证",
			})
			return errorx.NewError(errorx.Unauthorized, "用户未认证")
		}

		claims, err := validateToken(token, config.SecretKey)
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "token 验证失败",
			})
			return err
		}

		// 设置用户ID到上下文
		reqCtx := ctx.GetContext()
		reqCtx = hbasic.WithUserID(reqCtx, claims.UserID)

		tenantID := ctx.GetHeader(config.TenantHeader)
		if tenantID == "" && config.AllowTenantQuery {
			tenantID = ctx.GetQuery("tenant_id")
		}
		if tenantID == "" && config.RequireTenant {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "tenant_id is required",
			})
			return errorx.NewError(errorx.Validation, "tenant_id is required")
		}
		if tenantID != "" {
			reqCtx = hbasic.WithTenantID(reqCtx, tenantID)
		}

		// 注入角色与权限信息，供后续 RBAC 使用
		reqCtx = auth.WithRoles(reqCtx, claims.Roles)
		reqCtx = auth.WithPermissions(reqCtx, claims.Permissions)

		ctx.SetContext(reqCtx)

		// 继续处理
		return next()
	}
}

// OptionalAuthMiddleware 可选认证中间件
func OptionalAuthMiddleware(config *AuthConfig) httpx.Middleware {
	if config == nil {
		config = DefaultAuthConfig()
	}

	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.GetContext()
		tenantID := ctx.GetHeader(config.TenantHeader)
		if tenantID == "" && config.AllowTenantQuery {
			tenantID = ctx.GetQuery("tenant_id")
		}
		if tenantID == "" && config.RequireTenant {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "tenant_id is required",
			})
			return errorx.NewError(errorx.Validation, "tenant_id is required")
		}
		if tenantID != "" {
			reqCtx = hbasic.WithTenantID(reqCtx, tenantID)
			ctx.SetContext(reqCtx)
		}

		// 尝试获取token
		token := extractToken(ctx, config)
		if token != "" {
			// 如果有token，尝试验证
			if claims, err := validateToken(token, config.SecretKey); err == nil && claims != nil {
				// 验证成功，设置用户ID，并注入角色/权限信息
				reqCtx := ctx.GetContext()
				reqCtx = hbasic.WithUserID(reqCtx, claims.UserID)

				reqCtx = auth.WithRoles(reqCtx, claims.Roles)
				reqCtx = auth.WithPermissions(reqCtx, claims.Permissions)

				ctx.SetContext(reqCtx)
			}
		}

		// 无论是否认证成功都继续处理
		return next()
	}
}

func extractTokenFromHeadersAndQuery(getHeader func(string) string, getQuery func(string) string, config *AuthConfig) string {
	if config == nil {
		config = DefaultAuthConfig()
	}
	if getHeader != nil {
		authHeader := getHeader(config.TokenHeader)
		if authHeader != "" && strings.HasPrefix(authHeader, config.TokenPrefix) {
			return strings.TrimPrefix(authHeader, config.TokenPrefix)
		}
	}

	// 从查询参数中获取（默认禁用，避免 URL token 泄露到 access log / referer / 监控链路）
	if config.AllowQueryToken && getQuery != nil {
		if token := getQuery("token"); token != "" {
			return token
		}
	}

	return ""
}

// extractToken 提取 token
func extractToken(ctx httpx.IContext, config *AuthConfig) string {
	return extractTokenFromHeadersAndQuery(ctx.GetHeader, ctx.GetQuery, config)
}

// validateToken 验证token并返回声明
func validateToken(token, secretKey string) (*JWTClaims, error) {
	claims, err := ParseToken(token, secretKey)
	if err != nil {
		return nil, err
	}
	if claims == nil || claims.UserID <= 0 {
		return nil, errorx.NewError(errorx.Unauthorized, "无效的token")
	}
	return claims, nil
}

// JWTClaims JWT声明结构
type JWTClaims struct {
	UserID      int64    `json:"user_id"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 JWT 访问令牌
func GenerateToken(userID int64, username string, roles, permissions []string, secretKey string) (string, error) {
	return GenerateTokenWithTTL(userID, username, roles, permissions, secretKey, defaultAccessTokenTTL)
}

// GenerateTokenWithTTL 生成 JWT 访问令牌（可配置 TTL）
func GenerateTokenWithTTL(userID int64, username string, roles, permissions []string, secretKey string, ttl time.Duration) (string, error) {
	if secretKey == "" {
		return "", errorx.NewError(errorx.Internal, "JWT 密钥未配置")
	}
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}

	now := time.Now()
	claims := &JWTClaims{
		UserID:      userID,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", errorx.NewError(errorx.Internal, "生成token失败")
	}
	return signed, nil
}

// ParseToken 解析并验证 JWT 令牌
func ParseToken(tokenStr, secretKey string) (*JWTClaims, error) {
	// 测试令牌支持：仅在明确启用时生效（开发/测试环境）
	// 生产环境必须确保 ALLOW_TEST_TOKEN 未设置或为 false
	if tokenStr == "test-token" && isTestTokenAllowed() {
		return &JWTClaims{
			UserID:   1,
			Username: "admin",
			Roles:    []string{"system_admin", "user"},
			Permissions: []string{
				"system:read", "system:write", "system:delete",
				"user:read", "user:write", "user:delete",
				"group:read", "group:write", "group:delete",
				"role:read", "role:write", "role:delete",
				"story:admin", "mcp:invoke",
			},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}, nil
	}

	if secretKey == "" {
		return nil, errorx.NewError(errorx.Unauthorized, "认证配置错误")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errorx.NewError(errorx.Unauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errorx.NewError(errorx.Unauthorized, "token 解析失败")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errorx.NewError(errorx.Unauthorized, "无效的token")
	}

	return claims, nil
}

// RefreshToken 刷新token
func RefreshToken(token, secretKey string) (string, error) {
	// 测试令牌：仅在允许时直接返回
	if token == "test-token" && isTestTokenAllowed() {
		return token, nil
	}

	// 解析旧token
	claims, err := ParseToken(token, secretKey)
	if err != nil {
		return "", err
	}

	// 生成新token
	return GenerateToken(claims.UserID, claims.Username, claims.Roles, claims.Permissions, secretKey)
}

// isTestTokenAllowed 检查是否允许使用测试令牌
// 通过环境变量 ALLOW_TEST_TOKEN 控制，默认不允许
// 生产环境必须确保此变量未设置或为 false
func isTestTokenAllowed() bool {
	if !isDevEnv() {
		return false
	}
	v := os.Getenv("ALLOW_TEST_TOKEN")
	return v == "true" || v == "1"
}
