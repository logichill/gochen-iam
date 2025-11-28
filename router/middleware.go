package router

import (
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"gochen/errors"
	httpx "gochen/httpx"
)

type contextKey string

const (
	contextKeyRoles       contextKey = "auth_roles"
	contextKeyPermissions contextKey = "auth_permissions"
)

// AuthConfig 认证配置
type AuthConfig struct {
	SecretKey    string   `json:"secret_key" yaml:"secret_key"`
	TokenHeader  string   `json:"token_header" yaml:"token_header"`
	TokenPrefix  string   `json:"token_prefix" yaml:"token_prefix"`
	SkipPaths    []string `json:"skip_paths" yaml:"skip_paths"`
	RequiredRole string   `json:"required_role" yaml:"required_role"`
}

// DefaultAuthConfig 默认认证配置
func DefaultAuthConfig() *AuthConfig {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "your-secret-key"
	}
	return &AuthConfig{
		SecretKey:   secret,
		TokenHeader: "Authorization",
		TokenPrefix: "Bearer ",
		SkipPaths: []string{
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/health",
			"/api/v1/ping",
		},
	}
}

// JWTClaims JWT 声明
type JWTClaims struct {
	UserID      int64    `json:"user_id"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken 生成 JWT 访问令牌
func GenerateToken(userID int64, username string, roles, permissions []string, secretKey string) (string, error) {
	claims := &JWTClaims{
		UserID:      userID,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", errors.WrapError(err, errors.ErrCodeInternal, "生成 token 失败")
	}
	return signedToken, nil
}

// RefreshToken 刷新 JWT 令牌
func RefreshToken(tokenString, secretKey string) (string, error) {
	claims, err := validateToken(tokenString, secretKey)
	if err != nil {
		return "", err
	}
	return GenerateToken(claims.UserID, claims.Username, claims.Roles, claims.Permissions, secretKey)
}

// AdminOnlyMiddleware 仅管理员中间件
func AdminOnlyMiddleware() httpx.Middleware {
	return RoleMiddleware("system_admin")
}

// UserOnlyMiddleware 仅用户中间件（已认证用户）
func UserOnlyMiddleware() httpx.Middleware {
	return func(ctx httpx.IHttpContext, next func() error) error {
		if ctx.GetContext().GetUserID() == 0 {
			return errors.NewError(errors.ErrCodeUnauthorized, "用户未认证")
		}
		return next()
	}
}

// RoleMiddleware 角色验证中间件
func RoleMiddleware(requiredRole string) httpx.Middleware {
	return func(ctx httpx.IHttpContext, next func() error) error {
		reqCtx := ctx.GetContext()
		if reqCtx == nil || reqCtx.GetUserID() == 0 {
			return errors.NewError(errors.ErrCodeUnauthorized, "用户未认证")
		}

		if err := RequireAnyRole(reqCtx, requiredRole); err != nil {
			return err
		}
		return next()
	}
}

// RequireAnyRole 检查是否拥有任一指定角色
func RequireAnyRole(ctx httpx.IRequestContext, roles ...string) error {
	if ctx == nil {
		return errors.NewError(errors.ErrCodeUnauthorized, "用户未认证")
	}
	userRoles := GetRoles(ctx)
	for _, role := range roles {
		for _, userRole := range userRoles {
			if strings.EqualFold(userRole, role) {
				return nil
			}
		}
	}
	return errors.NewError(errors.ErrCodeForbidden, "缺少所需角色")
}

// RequirePermission 检查是否拥有指定权限
func RequirePermission(ctx httpx.IRequestContext, permission string) error {
	if ctx == nil {
		return errors.NewError(errors.ErrCodeUnauthorized, "用户未认证")
	}
	userPermissions := GetPermissions(ctx)
	for _, p := range userPermissions {
		if strings.EqualFold(p, permission) {
			return nil
		}
	}
	return errors.NewError(errors.ErrCodeForbidden, "缺少所需权限")
}

// GetRoles 从请求上下文获取角色列表
func GetRoles(ctx httpx.IRequestContext) []string {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(contextKeyRoles); val != nil {
		if roles, ok := val.([]string); ok {
			return roles
		}
	}
	return nil
}

// GetPermissions 从请求上下文获取权限列表
func GetPermissions(ctx httpx.IRequestContext) []string {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(contextKeyPermissions); val != nil {
		if permissions, ok := val.([]string); ok {
			return permissions
		}
	}
	return nil
}

// validateToken 解析并验证 JWT
func validateToken(tokenString, secretKey string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewError(errors.ErrCodeUnauthorized, "不支持的签名方法")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeUnauthorized, "token 验证失败")
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.NewError(errors.ErrCodeUnauthorized, "无效的 token")
}
