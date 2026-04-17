package middleware

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/tenant"
	ctxx "gochen/contextx"
	"gochen/errorx"
	"gochen/httpx"
)

const (
	envAccessTokenTTL      = "AUTH_ACCESS_TOKEN_TTL"
	envAllowQueryToken     = "AUTH_ALLOW_QUERY_TOKEN"
	envRequireTenant       = "AUTH_REQUIRE_TENANT"
	envAllowTenantQuery    = "AUTH_ALLOW_TENANT_QUERY"
	envTenantHeader        = "AUTH_TENANT_HEADER"
	defaultAccessTokenTTL  = 24 * time.Hour
	defaultActivationTTL   = 10 * time.Minute
	defaultTenantHeaderKey = httpx.HeaderTenantID
)

// ResolvedAuthContext 表达把 access token 还原成运行时请求边界所需的最小元数据。
type ResolvedAuthContext struct {
	ActiveScopeID   int64
	ActiveScopeKind string
	VisibleScopeIDs []int64
}

// AuthContextResolver 负责把 access token 中的最小 claims 还原成运行时可消费的授权边界。
type AuthContextResolver interface {
	ResolveAuthContext(ctx context.Context, claims *JWTClaims) (*ResolvedAuthContext, error)
}

// AuthConfig 认证配置
type AuthConfig struct {
	SecretKey    string   `json:"secret_key" yaml:"secret_key"`
	TokenHeader  string   `json:"token_header" yaml:"token_header"`
	TokenPrefix  string   `json:"token_prefix" yaml:"token_prefix"`
	SkipPaths    []string `json:"skip_paths" yaml:"skip_paths"`
	RequiredRole string   `json:"required_role" yaml:"required_role"`

	AccessTokenTTL   time.Duration `json:"-" yaml:"-"`
	ActivationTTL    time.Duration `json:"-" yaml:"-"`
	AllowQueryToken  bool          `json:"-" yaml:"-"`
	RequireTenant    bool          `json:"-" yaml:"-"`
	AllowTenantQuery bool          `json:"-" yaml:"-"`
	TenantHeader     string        `json:"-" yaml:"-"`
	ContextResolver  AuthContextResolver `json:"-" yaml:"-"`
}

var installedAuthContextResolver AuthContextResolver

// InstallAuthContextResolver 注册 access token 运行时上下文还原器。
func InstallAuthContextResolver(resolver AuthContextResolver) {
	installedAuthContextResolver = resolver
}

func resolveAuthContextResolver(config *AuthConfig) AuthContextResolver {
	if config != nil && config.ContextResolver != nil {
		return config.ContextResolver
	}
	return installedAuthContextResolver
}

// ResolveInstalledAuthContextResolver 返回当前安装的 access token 上下文还原器。
func ResolveInstalledAuthContextResolver() AuthContextResolver {
	return installedAuthContextResolver
}

// DefaultAuthConfig 默认认证配置
// 必须设置 AUTH_SECRET 环境变量
func DefaultAuthConfig() *AuthConfig {
	secret := os.Getenv("AUTH_SECRET")

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
		ActivationTTL:    defaultActivationTTL,
		AllowQueryToken:  (os.Getenv(envAllowQueryToken) == "true" || os.Getenv(envAllowQueryToken) == "1") && isDevEnv(),
		RequireTenant:    os.Getenv(envRequireTenant) == "true" || os.Getenv(envRequireTenant) == "1",
		AllowTenantQuery: os.Getenv(envAllowTenantQuery) == "true" || os.Getenv(envAllowTenantQuery) == "1",
		TenantHeader:     tenantHeader,
		SkipPaths: []string{
			"/api/v1/auth/login",
			"/api/v1/auth/activate-scope",
			"/api/v1/auth/register",
			"/api/v1/health",
			"/api/v1/ping",
		},
	}
}

// isDevEnv 检查是否为开发/测试环境
// 通过 APP_ENV 环境变量判断
func isDevEnv() bool {
	env := os.Getenv("APP_ENV")
	return env == "development" || env == "dev" || env == "test" || env == "testing"
}

// IsDevEnv 对外暴露统一的 dev/test 环境判定。
func IsDevEnv() bool { return isDevEnv() }

// ValidateAuthConfig 验证认证配置是否完整
// 应在应用启动时调用；缺少必要配置时返回错误（生产环境还会附加更严格的安全约束校验）。
func ValidateAuthConfig(config *AuthConfig) error {
	if config == nil {
		config = DefaultAuthConfig()
	}
	if config.SecretKey == "" {
		return errorx.New(errorx.Internal, "必须设置 AUTH_SECRET 环境变量")
	}
	// 生产环境禁止允许 query token，避免 token 泄露到 URL/日志链路。
	if !isDevEnv() && config.AllowQueryToken {
		return errorx.New(errorx.Internal, "生产环境禁止启用 AUTH_ALLOW_QUERY_TOKEN")
	}
	return nil
}

// matchSkipPath 处理matchSkipPath。
func matchSkipPath(path, skipPath string) bool {
	if skipPath == "" {
		return false
	}
	if strings.HasSuffix(skipPath, "/") {
		return strings.HasPrefix(path, skipPath)
	}
	return path == skipPath || path == skipPath+"/"
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
	var validateOnce sync.Once
	var validateErr error

	return func(ctx httpx.IContext, next func() error) error {
		// 检查是否需要跳过认证
		path := ctx.Path()
		for _, skipPath := range config.SkipPaths {
			if matchSkipPath(path, skipPath) {
				return next()
			}
		}

		// 严格权限字典：运行期兜底 fail-close（防止上层装配期校验遗漏/被吞掉）。
		// 注意：放在 SkipPaths 后，保证 health/无需鉴权路由仍可用。
		if err := EnsureStrictPermissionRegistryLoaded(); err != nil {
			return err
		}

		// 获取 token（必需鉴权：无 token 直接拒绝；如需可选鉴权请使用 OptionalAuthMiddleware）
		token := extractToken(ctx, config)
		if token == "" {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "用户未认证",
			})
			return errorx.New(errorx.Unauthorized, "用户未认证")
		}

		// 对于必需鉴权，仅在“确实需要解析 token”时才做配置校验；
		// 这样缺少 token 时能返回 401，而不是因 AUTH_SECRET 缺失返回 500。
		validateOnce.Do(func() {
			validateErr = ValidateAuthConfig(config)
		})
		if validateErr != nil {
			return validateErr
		}

		claims, err := validateToken(token, config.SecretKey)
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "token 验证失败",
			})
			return err
		}

		reqCtx := ctx.RequestContext()

		tenantID, err := tenant.ResolveRequestTenantID(readRequestTenantID(ctx, config), "", config.RequireTenant)
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   err.Error(),
			})
			return err
		}
		reqCtx, err = InjectClaimsRequestContext(reqCtx, tenantID, claims, resolveAuthContextResolver(config))
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "invalid auth claims context",
			})
			return err
		}

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
	var validateOnce sync.Once
	var validateErr error

	return func(ctx httpx.IContext, next func() error) error {
		// 检查是否需要跳过认证
		path := ctx.Path()
		for _, skipPath := range config.SkipPaths {
			if matchSkipPath(path, skipPath) {
				return next()
			}
		}

		// 严格权限字典：运行期兜底 fail-close（防止上层装配期校验遗漏/被吞掉）。
		if err := EnsureStrictPermissionRegistryLoaded(); err != nil {
			return err
		}

		reqCtx := ctx.RequestContext()
		requestTenantID := readRequestTenantID(ctx, config)
		tenantID := requestTenantID
		if tenant.Current().IsSingle() {
			var err error
			tenantID, err = tenant.ResolveRequestTenantID(requestTenantID, "", config.RequireTenant)
			if err != nil {
				recordAuthzDenied(ctx, AuditRecord{
					Decision: "deny",
					Reason:   err.Error(),
				})
				return err
			}
		}
		if tenantID != "" {
			derived, err := ctxx.WithTenantID(reqCtx, tenantID)
			if err != nil {
				recordAuthzDenied(ctx, AuditRecord{
					Decision: "deny",
					Reason:   "invalid tenant_id",
				})
				return err
			}
			reqCtx = reqCtx.WithContext(derived)
			ctx.SetContext(reqCtx)
		}

		// 尝试获取token
		token := extractToken(ctx, config)
		if token == "" {
			if tenantID == "" && config.RequireTenant {
				err := errorx.New(errorx.Validation, "tenant_id is required")
				recordAuthzDenied(ctx, AuditRecord{
					Decision: "deny",
					Reason:   err.Error(),
				})
				return err
			}
			// 无 token：保持匿名请求，不校验 AUTH_SECRET（避免误把“缺 token”变成 500）。
			return next()
		}

		// 有 token：此时才需要校验鉴权配置（尤其是 AUTH_SECRET）。
		validateOnce.Do(func() {
			validateErr = ValidateAuthConfig(config)
		})
		if validateErr != nil {
			return validateErr
		}

		// 如果有 token：必须是有效 token；否则返回 401（fail-close）。
		claims, err := validateToken(token, config.SecretKey)
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "token 验证失败",
			})
			return err
		}

		tenantID, err = tenant.ResolveRequestTenantID(requestTenantID, tenantID, config.RequireTenant)
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   err.Error(),
			})
			return err
		}
		reqCtx, err = InjectClaimsRequestContext(reqCtx, tenantID, claims, resolveAuthContextResolver(config))
		if err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "invalid auth claims context",
			})
			return err
		}
		ctx.SetContext(reqCtx)

		// 认证成功后继续处理（无 token 已在上方直接放行；有 token 但无效会返回 401）。
		return next()
	}
}

// extractTokenFromHeadersAndQuery 提取令牌从请求头集合And查询。
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
	return extractTokenFromHeadersAndQuery(ctx.Header, ctx.Query, config)
}

func readRequestTenantID(ctx httpx.IContext, config *AuthConfig) string {
	if ctx == nil {
		return ""
	}
	tenantID := strings.TrimSpace(ctx.Header(config.TenantHeader))
	if tenantID == "" && config.AllowTenantQuery {
		tenantID = strings.TrimSpace(ctx.Query("tenant_id"))
	}
	return tenantID
}

// validateToken 校验令牌。
func validateToken(token, secretKey string) (*JWTClaims, error) {
	claims, err := ParseToken(token, secretKey)
	if err != nil {
		return nil, err
	}
	if claims == nil || claims.UserID <= 0 {
		return nil, errorx.New(errorx.Unauthorized, "无效的token")
	}
	return claims, nil
}

// JWTClaims 表达最终 access token 的最小授权语义。
type JWTClaims struct {
	UserID         int64    `json:"user_id"`
	ActiveScopeID  int64    `json:"active_scope_id"`
	BindingVersion string   `json:"binding_version,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// ActivationClaims 表达认证成功后的短期 scope 激活票据。
type ActivationClaims struct {
	UserID          int64    `json:"user_id"`
	BindingVersion  string   `json:"binding_version,omitempty"`
	AvailableScopes []int64  `json:"available_scope_ids,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 access token。
func GenerateToken(userID, activeScopeID int64, bindingVersion string, permissions []string, secretKey string) (string, error) {
	return GenerateTokenWithTTL(userID, activeScopeID, bindingVersion, permissions, secretKey, defaultAccessTokenTTL)
}

// GenerateTokenWithTTL 生成 access token（可配置 TTL）。
func GenerateTokenWithTTL(userID, activeScopeID int64, bindingVersion string, permissions []string, secretKey string, ttl time.Duration) (string, error) {
	if secretKey == "" {
		return "", errorx.New(errorx.Internal, "JWT 密钥未配置")
	}
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}
	now := time.Now()
	claims := &JWTClaims{
		UserID:         userID,
		ActiveScopeID:  activeScopeID,
		BindingVersion: strings.TrimSpace(bindingVersion),
		Permissions:    permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", errorx.New(errorx.Internal, "生成token失败")
	}
	return signed, nil
}

// GenerateActivationToken 生成认证成功后的短期 scope 激活票据。
func GenerateActivationToken(userID int64, bindingVersion string, availableScopeIDs []int64, secretKey string, ttl time.Duration) (string, error) {
	if secretKey == "" {
		return "", errorx.New(errorx.Internal, "JWT 密钥未配置")
	}
	if ttl <= 0 {
		ttl = defaultActivationTTL
	}
	now := time.Now()
	claims := &ActivationClaims{
		UserID:          userID,
		BindingVersion:  strings.TrimSpace(bindingVersion),
		AvailableScopes: append([]int64(nil), availableScopeIDs...),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", errorx.New(errorx.Internal, "生成激活票据失败")
	}
	return signed, nil
}

// ParseToken 解析并验证 JWT 令牌
func ParseToken(tokenStr, secretKey string) (*JWTClaims, error) {
	if secretKey == "" {
		return nil, errorx.New(errorx.Unauthorized, "认证配置错误")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errorx.New(errorx.Unauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errorx.New(errorx.Unauthorized, "token 解析失败")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errorx.New(errorx.Unauthorized, "无效的token")
	}

	return claims, nil
}

// ParseActivationToken 解析并验证激活票据。
func ParseActivationToken(tokenStr, secretKey string) (*ActivationClaims, error) {
	if secretKey == "" {
		return nil, errorx.New(errorx.Unauthorized, "认证配置错误")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &ActivationClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errorx.New(errorx.Unauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errorx.New(errorx.Unauthorized, "activation token 解析失败")
	}

	claims, ok := token.Claims.(*ActivationClaims)
	if !ok || !token.Valid || claims.UserID <= 0 {
		return nil, errorx.New(errorx.Unauthorized, "无效的 activation token")
	}
	return claims, nil
}

// RefreshToken 刷新 access token。
func RefreshToken(token, secretKey string) (string, error) {
	claims, err := ParseToken(token, secretKey)
	if err != nil {
		return "", err
	}
	return GenerateTokenWithTTL(
		claims.UserID,
		claims.ActiveScopeID,
		claims.BindingVersion,
		claims.Permissions,
		secretKey,
		defaultAccessTokenTTL,
	)
}
