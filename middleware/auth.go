package middleware

import (
	"container/heap"
	"context"
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"gochen-iam/tenant"
	"gochen-runtime/http/nethttp"
	"gochen/contextx"
	"gochen/errors"
	"gochen/gen/uuid"
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
	tokenTypeAccess        = "access"
	tokenTypeActivation    = "activation"
	defaultRevokedTokenCap = 65536
	revokedTokenClockSkew  = 5 * time.Minute
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

const (
	// AccessTokenCookieName 是承载 access JWT 的 HttpOnly Cookie 名称。
	AccessTokenCookieName = "galaxy_access_token"
	// CSRFCookieName 是双重提交 CSRF 防护使用的可读 Cookie 名称。
	CSRFCookieName = "galaxy_csrf_token"
	// CSRFHeaderName 是必须与 CSRF Cookie 匹配的请求头名称。
	CSRFHeaderName = "X-CSRF-Token"
)

// AuthConfig 认证配置
type AuthConfig struct {
	SecretKey    string   `json:"secret_key" yaml:"secret_key"`
	TokenHeader  string   `json:"token_header" yaml:"token_header"`
	TokenPrefix  string   `json:"token_prefix" yaml:"token_prefix"`
	SkipPaths    []string `json:"skip_paths" yaml:"skip_paths"`
	RequiredRole string   `json:"required_role" yaml:"required_role"`

	AccessTokenTTL   time.Duration       `json:"-" yaml:"-"`
	ActivationTTL    time.Duration       `json:"-" yaml:"-"`
	AllowQueryToken  bool                `json:"-" yaml:"-"`
	RequireTenant    bool                `json:"-" yaml:"-"`
	AllowTenantQuery bool                `json:"-" yaml:"-"`
	TenantHeader     string              `json:"-" yaml:"-"`
	ContextResolver  AuthContextResolver `json:"-" yaml:"-"`

	// Cookie 传输配置；AccessTokenCookieName 为空时禁用 Cookie 认证。
	AccessTokenCookieName     string `json:"-" yaml:"-"`
	AccessTokenCookiePath     string `json:"-" yaml:"-"`
	AccessTokenCookieSameSite string `json:"-" yaml:"-"` // 可选值：lax、strict、none。
	AccessTokenCookieSecure   *bool  `json:"-" yaml:"-"` // nil 表示非开发环境启用 Secure。

	// Cookie 认证用于非安全方法时，通过可读 Cookie 与同值请求头执行双重提交 CSRF 校验。
	CSRFCookieName string `json:"-" yaml:"-"`
	CSRFCookiePath string `json:"-" yaml:"-"`
	CSRFHeaderName string `json:"-" yaml:"-"`
	// RevokedTokenStore 保存已轮转或吊销的 access token JTI；默认使用应用共享存储。
	RevokedTokenStore RevokedTokenStore `json:"-" yaml:"-"`
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
		SecretKey:                 secret,
		TokenHeader:               "Authorization",
		TokenPrefix:               "Bearer ",
		AccessTokenCookieName:     AccessTokenCookieName,
		AccessTokenCookiePath:     "/",
		AccessTokenCookieSameSite: "lax",
		CSRFCookieName:            CSRFCookieName,
		CSRFCookiePath:            "/",
		CSRFHeaderName:            CSRFHeaderName,
		RevokedTokenStore:         sharedRevokedTokenStore,
		AccessTokenTTL:            ttl,
		ActivationTTL:             defaultActivationTTL,
		AllowQueryToken:           (os.Getenv(envAllowQueryToken) == "true" || os.Getenv(envAllowQueryToken) == "1") && isDevEnv(),
		RequireTenant:             os.Getenv(envRequireTenant) == "true" || os.Getenv(envRequireTenant) == "1",
		AllowTenantQuery:          os.Getenv(envAllowTenantQuery) == "true" || os.Getenv(envAllowTenantQuery) == "1",
		TenantHeader:              tenantHeader,
		SkipPaths: []string{
			"/api/v1/auth/login",
			"/api/v1/auth/csrf",
			"/api/v1/auth/activate-scope",
			"/api/v1/auth/register",
			"/api/v1/iam/auth/login",
			"/api/v1/iam/auth/csrf",
			"/api/v1/iam/auth/activate-scope",
			"/api/v1/iam/auth/register",
			"/api/v1/iam/auth/forgot-password",
			"/api/v1/iam/auth/reset-password",
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
		return errors.NewCode(errors.Internal, "必须设置 AUTH_SECRET 环境变量")
	}
	// 生产环境禁止允许 query token，避免 token 泄露到 URL/日志链路。
	if !isDevEnv() && config.AllowQueryToken {
		return errors.NewCode(errors.Internal, "生产环境禁止启用 AUTH_ALLOW_QUERY_TOKEN")
	}
	if !isDevEnv() && !isPersistentRevokedTokenStore(config.RevokedTokenStore) {
		return errors.NewCode(errors.Internal, "非开发环境必须配置持久化 token 吊销存储")
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
			return errors.NewCode(errors.Unauthorized, "用户未认证")
		}

		// 对于必需鉴权，仅在“确实需要解析 token”时才做配置校验；
		// 这样缺少 token 时能返回 401，而不是因 AUTH_SECRET 缺失返回 500。
		validateOnce.Do(func() {
			validateErr = ValidateAuthConfig(config)
		})
		if validateErr != nil {
			return validateErr
		}

		if err := EnforceCSRFDoubleSubmit(ctx, config); err != nil {
			return err
		}
		claims, err := ValidateAccessToken(requestOperationContext(ctx), token, config)
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
			derived, err := contextx.WithTenantID(reqCtx, tenantID)
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
				err := errors.NewCode(errors.Validation, "tenant_id is required")
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
		if err := EnforceCSRFDoubleSubmit(ctx, config); err != nil {
			return err
		}
		claims, err := ValidateAccessToken(requestOperationContext(ctx), token, config)
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

// ExtractAccessToken 提取 access JWT，优先读取 Authorization 请求头，其次读取 HttpOnly Cookie。
func ExtractAccessToken(ctx httpx.IContext, config *AuthConfig) string {
	return extractToken(ctx, config)
}

func extractToken(ctx httpx.IContext, config *AuthConfig) string {
	if config == nil {
		config = DefaultAuthConfig()
	}
	if token := extractTokenFromHeadersAndQuery(ctx.Header, ctx.Query, config); token != "" {
		return token
	}
	return readAccessTokenCookie(ctx, config)
}

func requestOperationContext(ctx httpx.IContext) context.Context {
	if ctx == nil {
		return context.Background()
	}
	if reqCtx := ctx.RequestContext(); reqCtx != nil {
		return reqCtx
	}
	return context.Background()
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

// ValidateAccessToken 校验 access token 的用户身份、授权域与吊销状态。
func ValidateAccessToken(ctx context.Context, token string, config *AuthConfig) (*JWTClaims, error) {
	if ctx == nil {
		return nil, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	claims, err := ParseToken(token, config.SecretKey)
	if err != nil {
		return nil, err
	}
	if claims == nil || claims.UserID <= 0 || claims.ActiveScopeID <= 0 {
		return nil, errors.NewCode(errors.Unauthorized, "无效的token")
	}
	revoked, err := isAccessTokenRevoked(ctx, config, claims)
	if err != nil {
		return nil, errors.Wrap(err, errors.ServiceUnavailable, "token 吊销状态不可用")
	}
	if revoked {
		return nil, errors.NewCode(errors.Unauthorized, "token 已失效")
	}
	return claims, nil
}

// JWTClaims 表达最终 access token 的最小授权语义。
type JWTClaims struct {
	TokenType      string   `json:"token_type"`
	UserID         int64    `json:"user_id"`
	ActiveScopeID  int64    `json:"active_scope_id"`
	BindingVersion string   `json:"binding_version,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// ActivationClaims 表达认证成功后的短期 scope 激活票据。
type ActivationClaims struct {
	TokenType       string  `json:"token_type"`
	UserID          int64   `json:"user_id"`
	BindingVersion  string  `json:"binding_version,omitempty"`
	AvailableScopes []int64 `json:"available_scope_ids,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 access token。
func GenerateToken(userID, activeScopeID int64, bindingVersion string, permissions []string, secretKey string) (string, error) {
	return GenerateTokenWithTTL(userID, activeScopeID, bindingVersion, permissions, secretKey, defaultAccessTokenTTL)
}

// GenerateTokenWithTTL 生成 access token（可配置 TTL）。
func GenerateTokenWithTTL(userID, activeScopeID int64, bindingVersion string, permissions []string, secretKey string, ttl time.Duration) (string, error) {
	if secretKey == "" {
		return "", errors.NewCode(errors.Internal, "JWT 密钥未配置")
	}
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}
	now := time.Now()
	claims := &JWTClaims{
		TokenType:      tokenTypeAccess,
		UserID:         userID,
		ActiveScopeID:  activeScopeID,
		BindingVersion: strings.TrimSpace(bindingVersion),
		Permissions:    permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", errors.NewCode(errors.Internal, "生成token失败")
	}
	return signed, nil
}

// GenerateActivationToken 生成认证成功后的短期 scope 激活票据。
func GenerateActivationToken(userID int64, bindingVersion string, availableScopeIDs []int64, secretKey string, ttl time.Duration) (string, error) {
	if secretKey == "" {
		return "", errors.NewCode(errors.Internal, "JWT 密钥未配置")
	}
	if ttl <= 0 {
		ttl = defaultActivationTTL
	}
	now := time.Now()
	claims := &ActivationClaims{
		TokenType:       tokenTypeActivation,
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
		return "", errors.NewCode(errors.Internal, "生成激活票据失败")
	}
	return signed, nil
}

// ParseToken 解析并验证 JWT 令牌
func ParseToken(tokenStr, secretKey string) (*JWTClaims, error) {
	if secretKey == "" {
		return nil, errors.NewCode(errors.Unauthorized, "认证配置错误")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.NewCode(errors.Unauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errors.NewCode(errors.Unauthorized, "token 解析失败")
	}

	claims, ok := token.Claims.(*JWTClaims)
	legacyAccess := claims != nil && claims.TokenType == "" && claims.ActiveScopeID > 0
	if !ok || !token.Valid || (claims.TokenType != tokenTypeAccess && !legacyAccess) {
		return nil, errors.NewCode(errors.Unauthorized, "无效的token")
	}

	return claims, nil
}

// ParseActivationToken 解析并验证激活票据。
func ParseActivationToken(tokenStr, secretKey string) (*ActivationClaims, error) {
	if secretKey == "" {
		return nil, errors.NewCode(errors.Unauthorized, "认证配置错误")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &ActivationClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.NewCode(errors.Unauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errors.NewCode(errors.Unauthorized, "activation token 解析失败")
	}

	claims, ok := token.Claims.(*ActivationClaims)
	legacyActivation := claims != nil && claims.TokenType == "" && claims.UserID > 0 && len(claims.AvailableScopes) > 0
	if !ok || !token.Valid || (claims.TokenType != tokenTypeActivation && !legacyActivation) || claims.UserID <= 0 {
		return nil, errors.NewCode(errors.Unauthorized, "无效的 activation token")
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

func cookieSecure(config *AuthConfig) bool {
	if config != nil && config.AccessTokenCookieSecure != nil {
		return *config.AccessTokenCookieSecure
	}
	return !isDevEnv()
}

func cookieSameSite(config *AuthConfig) http.SameSite {
	mode := "lax"
	if config != nil && config.AccessTokenCookieSameSite != "" {
		mode = strings.ToLower(strings.TrimSpace(config.AccessTokenCookieSameSite))
	}
	switch mode {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func accessCookieName(config *AuthConfig) string {
	if config == nil {
		return AccessTokenCookieName
	}
	return strings.TrimSpace(config.AccessTokenCookieName)
}

func accessCookiePath(config *AuthConfig) string {
	if config == nil || strings.TrimSpace(config.AccessTokenCookiePath) == "" {
		return "/"
	}
	return strings.TrimSpace(config.AccessTokenCookiePath)
}

func readAccessTokenCookie(ctx httpx.IContext, config *AuthConfig) string {
	if ctx == nil {
		return ""
	}
	name := accessCookieName(config)
	if name == "" {
		return ""
	}
	req, ok := nethttp.RequestOf(ctx)
	if !ok {
		return ""
	}
	cookie, err := req.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

// WriteAccessTokenCookie 向响应写入承载 access token 的 HttpOnly Cookie。
func WriteAccessTokenCookie(ctx httpx.IContext, token string, config *AuthConfig) {
	if ctx == nil || strings.TrimSpace(token) == "" {
		return
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	name := accessCookieName(config)
	if name == "" {
		return
	}
	maxAge := int(config.AccessTokenTTL.Seconds())
	if maxAge <= 0 {
		maxAge = int(defaultAccessTokenTTL.Seconds())
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     accessCookiePath(config),
		HttpOnly: true,
		Secure:   cookieSecure(config),
		SameSite: cookieSameSite(config),
		MaxAge:   maxAge,
	}
	setCookieOnContext(ctx, cookie)
}

// ClearAccessTokenCookie 使 access token Cookie 立即过期。
func ClearAccessTokenCookie(ctx httpx.IContext, config *AuthConfig) {
	if ctx == nil {
		return
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	name := accessCookieName(config)
	if name == "" {
		return
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     accessCookiePath(config),
		HttpOnly: true,
		Secure:   cookieSecure(config),
		SameSite: cookieSameSite(config),
		MaxAge:   -1,
	}
	setCookieOnContext(ctx, cookie)
}

func setCookieOnContext(ctx httpx.IContext, cookie *http.Cookie) {
	if cookie == nil {
		return
	}
	if writer, ok := nethttp.ResponseWriterOf(ctx); ok && writer != nil {
		http.SetCookie(writer, cookie)
		return
	}
	// gin adapter also implements ResponseWriter(); type-assert broadly.
	if provider, ok := ctx.(interface{ ResponseWriter() http.ResponseWriter }); ok {
		if writer := provider.ResponseWriter(); writer != nil {
			http.SetCookie(writer, cookie)
			return
		}
	}
}

// RevokedTokenStore 原子消费 access token JTI，并查询其吊销状态。
type RevokedTokenStore interface {
	Consume(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

type memoryRevokedTokenStore struct {
	mu         sync.Mutex
	byID       map[string]time.Time
	expiries   revokedTokenExpiryHeap
	maxEntries int
}

type revokedTokenExpiry struct {
	jti       string
	expiresAt time.Time
}

type revokedTokenExpiryHeap []revokedTokenExpiry

func (h revokedTokenExpiryHeap) Len() int           { return len(h) }
func (h revokedTokenExpiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h revokedTokenExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *revokedTokenExpiryHeap) Push(value any)    { *h = append(*h, value.(revokedTokenExpiry)) }
func (h *revokedTokenExpiryHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// NewMemoryRevokedTokenStore 创建仅适用于开发和测试的进程内吊销存储。
func NewMemoryRevokedTokenStore() RevokedTokenStore {
	return newMemoryRevokedTokenStore()
}

func newMemoryRevokedTokenStore() *memoryRevokedTokenStore {
	return newMemoryRevokedTokenStoreWithLimit(defaultRevokedTokenCap)
}

func newMemoryRevokedTokenStoreWithLimit(maxEntries int) *memoryRevokedTokenStore {
	return &memoryRevokedTokenStore{byID: make(map[string]time.Time), maxEntries: maxEntries}
}

func (s *memoryRevokedTokenStore) Consume(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if ctx == nil {
		return false, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Wrap(err, errors.ServiceUnavailable, "token 吊销操作已取消")
	}
	jti = strings.TrimSpace(jti)
	if jti == "" || expiresAt.IsZero() {
		return false, errors.NewCode(errors.InvalidInput, "token JTI 与过期时间不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.removeExpiredLocked(now)
	if current, exists := s.byID[jti]; exists && now.Before(current.Add(revokedTokenClockSkew)) {
		return false, nil
	}
	if s.maxEntries > 0 && len(s.byID) >= s.maxEntries {
		return false, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储容量已满")
	}
	s.byID[jti] = expiresAt
	heap.Push(&s.expiries, revokedTokenExpiry{jti: jti, expiresAt: expiresAt})
	return true, nil
}

func (s *memoryRevokedTokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if ctx == nil {
		return false, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Wrap(err, errors.ServiceUnavailable, "token 吊销查询已取消")
	}
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.removeExpiredLocked(now)
	exp, ok := s.byID[jti]
	if !ok {
		return false, nil
	}
	if !now.Before(exp.Add(revokedTokenClockSkew)) {
		delete(s.byID, jti)
		return false, nil
	}
	return true, nil
}

func (s *memoryRevokedTokenStore) removeExpiredLocked(now time.Time) {
	for s.expiries.Len() > 0 && !now.Before(s.expiries[0].expiresAt.Add(revokedTokenClockSkew)) {
		entry := heap.Pop(&s.expiries).(revokedTokenExpiry)
		if current, ok := s.byID[entry.jti]; ok && current.Equal(entry.expiresAt) {
			delete(s.byID, entry.jti)
		}
	}
}

type sharedRevokedTokenStoreProxy struct {
	mu      sync.RWMutex
	backing RevokedTokenStore
}

func newSharedRevokedTokenStoreProxy() *sharedRevokedTokenStoreProxy {
	return &sharedRevokedTokenStoreProxy{backing: newMemoryRevokedTokenStore()}
}

func (s *sharedRevokedTokenStoreProxy) install(store RevokedTokenStore) error {
	if store == nil {
		return errors.NewCode(errors.InvalidInput, "token 吊销存储不能为空")
	}
	s.mu.Lock()
	s.backing = store
	s.mu.Unlock()
	return nil
}

func (s *sharedRevokedTokenStoreProxy) current() RevokedTokenStore {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	store := s.backing
	s.mu.RUnlock()
	return store
}

func (s *sharedRevokedTokenStoreProxy) Consume(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	store := s.current()
	if store == nil {
		return false, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储不可用")
	}
	return store.Consume(ctx, jti, expiresAt)
}

func (s *sharedRevokedTokenStoreProxy) IsRevoked(ctx context.Context, jti string) (bool, error) {
	store := s.current()
	if store == nil {
		return false, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储不可用")
	}
	return store.IsRevoked(ctx, jti)
}

var sharedRevokedTokenStore = newSharedRevokedTokenStoreProxy()

// InstallDefaultRevokedTokenStore 替换 DefaultAuthConfig 使用的共享吊销存储。
func InstallDefaultRevokedTokenStore(store RevokedTokenStore) error {
	return sharedRevokedTokenStore.install(store)
}

func isPersistentRevokedTokenStore(store RevokedTokenStore) bool {
	switch typed := store.(type) {
	case nil:
		return false
	case *memoryRevokedTokenStore:
		return false
	case *sharedRevokedTokenStoreProxy:
		return isPersistentRevokedTokenStore(typed.current())
	default:
		return true
	}
}

func revokedStore(config *AuthConfig) RevokedTokenStore {
	if config != nil && config.RevokedTokenStore != nil {
		return config.RevokedTokenStore
	}
	return sharedRevokedTokenStore
}

// ConsumeAccessTokenJTI 原子吊销尚未消费的 access token JTI。
func ConsumeAccessTokenJTI(ctx context.Context, config *AuthConfig, jti string, expiresAt time.Time) (bool, error) {
	return revokedStore(config).Consume(ctx, jti, expiresAt)
}

// RevokeAccessTokenJTI 将 access token JTI 标记为不可再使用。
func RevokeAccessTokenJTI(ctx context.Context, config *AuthConfig, jti string, expiresAt time.Time) error {
	_, err := ConsumeAccessTokenJTI(ctx, config, jti, expiresAt)
	return err
}

func isAccessTokenRevoked(ctx context.Context, config *AuthConfig, claims *JWTClaims) (bool, error) {
	if claims == nil {
		return false, nil
	}
	return revokedStore(config).IsRevoked(ctx, claims.ID)
}

func csrfCookieName(config *AuthConfig) string {
	if config != nil && strings.TrimSpace(config.CSRFCookieName) != "" {
		return strings.TrimSpace(config.CSRFCookieName)
	}
	return CSRFCookieName
}

func csrfHeaderName(config *AuthConfig) string {
	if config != nil && strings.TrimSpace(config.CSRFHeaderName) != "" {
		return strings.TrimSpace(config.CSRFHeaderName)
	}
	return CSRFHeaderName
}

func csrfCookiePath(config *AuthConfig) string {
	if config != nil && strings.TrimSpace(config.CSRFCookiePath) != "" {
		return strings.TrimSpace(config.CSRFCookiePath)
	}
	return "/"
}

func expireCSRFCookie(ctx httpx.IContext, config *AuthConfig, path string) {
	cookie := &http.Cookie{
		Name:     csrfCookieName(config),
		Value:    "",
		Path:     path,
		HttpOnly: false,
		Secure:   cookieSecure(config),
		SameSite: cookieSameSite(config),
		MaxAge:   -1,
	}
	setCookieOnContext(ctx, cookie)
}

func csrfCookiePaths(config *AuthConfig) []string {
	currentPath := csrfCookiePath(config)
	legacyPath := accessCookiePath(config)
	if legacyPath == "" || legacyPath == currentPath {
		return []string{currentPath}
	}
	return []string{currentPath, legacyPath}
}

// WriteCSRFCookie 写入双重提交校验使用的可读 CSRF Cookie。
func WriteCSRFCookie(ctx httpx.IContext, config *AuthConfig) string {
	if ctx == nil {
		return ""
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	if accessCookieName(config) == "" {
		return ""
	}
	paths := csrfCookiePaths(config)
	for _, path := range paths[1:] {
		expireCSRFCookie(ctx, config, path)
	}
	token := uuid.NewString()
	maxAge := int(config.AccessTokenTTL.Seconds())
	if maxAge <= 0 {
		maxAge = int(defaultAccessTokenTTL.Seconds())
	}
	cookie := &http.Cookie{
		Name:     csrfCookieName(config),
		Value:    token,
		Path:     csrfCookiePath(config),
		HttpOnly: false,
		Secure:   cookieSecure(config),
		SameSite: cookieSameSite(config),
		MaxAge:   maxAge,
	}
	setCookieOnContext(ctx, cookie)
	return token
}

// EnsureCSRFCookie 返回当前 CSRF Cookie，缺失时生成并写入一个新值。
func EnsureCSRFCookie(ctx httpx.IContext, config *AuthConfig) string {
	if ctx == nil {
		return ""
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	if accessCookieName(config) == "" {
		return ""
	}
	if req, ok := nethttp.RequestOf(ctx); ok {
		name := csrfCookieName(config)
		for _, cookie := range req.Cookies() {
			if cookie.Name == name {
				if value := strings.TrimSpace(cookie.Value); value != "" {
					return value
				}
			}
		}
	}
	return WriteCSRFCookie(ctx, config)
}

// ClearCSRFCookie 使 CSRF Cookie 立即过期。
func ClearCSRFCookie(ctx httpx.IContext, config *AuthConfig) {
	if ctx == nil {
		return
	}
	if config == nil {
		config = DefaultAuthConfig()
	}
	if accessCookieName(config) == "" {
		return
	}
	for _, path := range csrfCookiePaths(config) {
		expireCSRFCookie(ctx, config, path)
	}
}

func hasMatchingCSRFCookie(ctx httpx.IContext, config *AuthConfig, expected string) bool {
	if ctx == nil || expected == "" {
		return false
	}
	req, ok := nethttp.RequestOf(ctx)
	if !ok {
		return false
	}
	name := csrfCookieName(config)
	for _, cookie := range req.Cookies() {
		value := strings.TrimSpace(cookie.Value)
		if cookie.Name == name && subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

// EnforceCSRFDoubleSubmit 在 Cookie 认证的非安全方法上校验双重提交 CSRF token。
func EnforceCSRFDoubleSubmit(ctx httpx.IContext, config *AuthConfig) error {
	if ctx == nil {
		return nil
	}
	method := strings.ToUpper(ctx.Method())
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return nil
	}
	// Header/query token 优先于 Cookie；只有实际回退到 Cookie 认证时才要求 CSRF。
	if token := extractTokenFromHeadersAndQuery(ctx.Header, ctx.Query, config); token != "" {
		return nil
	}
	if readAccessTokenCookie(ctx, config) == "" {
		return nil
	}
	headerToken := strings.TrimSpace(ctx.Header(csrfHeaderName(config)))
	if !hasMatchingCSRFCookie(ctx, config, headerToken) {
		return errors.NewCode(errors.Forbidden, "CSRF token 校验失败")
	}
	return nil
}
