package router

import (
	"strings"
	"time"

	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	"gochen-iam/tenant"
	ctxx "gochen/contextx"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// AuthRoutes 认证路由注册器
type AuthRoutes struct {
	userService IUserService
	utils       *hbasic.Utils
	authConfig  *iammw.AuthConfig
}

// NewAuthRoutes 创建认证路由注册器
func NewAuthRoutes(userService IUserService) *AuthRoutes {
	return &AuthRoutes{
		userService: userService,
		utils:       &hbasic.Utils{},
		authConfig:  iammw.DefaultAuthConfig(),
	}
}

// RegisterRoutes 注册路由。
func (ar *AuthRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	authGroup := group.Group("/auth")

	authGroup.POST("/register", ar.register)
	authGroup.POST("/login", ar.login)
	authGroup.POST("/logout", ar.logout)
	authGroup.POST("/refresh", ar.refreshToken)
	authGroup.POST("/forgot-password", ar.forgotPassword)
	authGroup.POST("/reset-password", ar.resetPassword)
	return nil
}

// GetName 获取注册器名称
func (ar *AuthRoutes) GetName() string {
	return "auth"
}

// GetPriority 获取注册优先级
func (ar *AuthRoutes) GetPriority() int {
	return 10 // 认证路由优先级最高
}

func (ar *AuthRoutes) readRequestTenantID(ctx httpx.IContext) string {
	if ctx == nil {
		return ""
	}
	cfg := ar.authConfig
	if cfg == nil {
		cfg = iammw.DefaultAuthConfig()
	}
	tenantID := strings.TrimSpace(ctx.Header(cfg.TenantHeader))
	if tenantID == "" && cfg.AllowTenantQuery {
		tenantID = strings.TrimSpace(ctx.Query("tenant_id"))
	}
	return tenantID
}

func (ar *AuthRoutes) ensureTenantContext(ctx httpx.IContext) (httpx.IRequestContext, string, error) {
	reqCtx := ctx.RequestContext()
	currentTenantID := ctxx.GetTenantID(reqCtx)
	cfg := ar.authConfig
	if cfg == nil {
		cfg = iammw.DefaultAuthConfig()
	}
	tenantID, err := tenant.ResolveRequestTenantID(ar.readRequestTenantID(ctx), currentTenantID, cfg.RequireTenant)
	if err != nil {
		return reqCtx, "", err
	}
	if tenantID == "" || currentTenantID == tenantID {
		return reqCtx, tenantID, nil
	}
	derived, err := ctxx.WithTenantID(reqCtx, tenantID)
	if err != nil {
		return reqCtx, "", err
	}
	reqCtx = reqCtx.WithContext(derived)
	ctx.SetContext(reqCtx)
	return reqCtx, tenantID, nil
}

// 认证处理器方法
func (ar *AuthRoutes) register(ctx httpx.IContext) error {
	reqCtx, tenantID, err := ar.ensureTenantContext(ctx)
	if err != nil {
		return err
	}
	req := &iamsvc.RegisterRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}

	user, err := ar.userService.Register(reqCtx, tenantID, req)
	if err != nil {
		return err
	}

	if user != nil {
		user.Password = ""
	}

	return httpx.WriteSuccess(ctx, user)
}

// login 处理login。
func (ar *AuthRoutes) login(ctx httpx.IContext) error {
	reqCtx, tenantID, err := ar.ensureTenantContext(ctx)
	if err != nil {
		return err
	}
	req := &iamsvc.AuthenticateRequest{}
	if err := ctx.BindJSON(req); err != nil {
		return err
	}
	authResult, err := ar.userService.Authenticate(reqCtx, tenantID, req)
	if err != nil {
		return err
	}

	// 基于用户信息生成 JWT，携带角色与权限声明
	token, err := iammw.GenerateTokenWithScope(
		authResult.UserID,
		authResult.TenantID,
		authResult.Username,
		authResult.Roles,
		authResult.Permissions,
		authResult.ActiveScopeID,
		authResult.ActiveScopeKey,
		authResult.ActiveScopeType,
		ar.authConfig.SecretKey,
		ar.authConfig.AccessTokenTTL,
	)
	if err != nil {
		return err
	}

	// 注意：HTTP 层返回 token/expires_at；service 层不包含 token 语义。
	type loginResponse struct {
		UserID      int64     `json:"user_id"`
		Username    string    `json:"username"`
		Email       string    `json:"email"`
		Token       string    `json:"token"`
		ExpiresAt   time.Time `json:"expires_at"`
		Permissions []string  `json:"permissions"`
	}
	resp := &loginResponse{
		UserID:      authResult.UserID,
		Username:    authResult.Username,
		Email:       authResult.Email,
		Token:       token,
		ExpiresAt:   time.Now().Add(ar.authConfig.AccessTokenTTL),
		Permissions: authResult.Permissions,
	}

	return httpx.WriteSuccess(ctx, resp)
}

// logout 处理logout。
func (ar *AuthRoutes) logout(ctx httpx.IContext) error {
	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"message": "logged_out",
	})
}

// refreshToken 处理refresh令牌。
func (ar *AuthRoutes) refreshToken(ctx httpx.IContext) error {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	if req.Token == "" {
		err := errorx.New(errorx.Validation, "token is required")
		return err
	}

	// 1) 验证旧 token
	claims, err := iammw.ParseToken(req.Token, ar.authConfig.SecretKey)
	if err != nil {
		return err
	}

	reqCtx := ctx.RequestContext()
	requestTenantID := ar.readRequestTenantID(ctx)
	if requestTenantID == "" {
		requestTenantID = ctxx.GetTenantID(reqCtx)
	}
	tenantID, err := tenant.ResolveRequestTenantIDWithScope(requestTenantID, strings.TrimSpace(claims.TenantID), claims.ActiveScopeType, true)
	if err != nil {
		return err
	}
	if strings.TrimSpace(ctxx.GetTenantID(reqCtx)) != tenantID {
		derived, err := ctxx.WithTenantID(reqCtx, tenantID)
		if err != nil {
			return err
		}
		reqCtx = reqCtx.WithContext(derived)
		ctx.SetContext(reqCtx)
	}
	reqCtx = iamauth.WithRoles(reqCtx, claims.Roles)
	reqCtx = iamauth.WithPermissions(reqCtx, claims.Permissions)
	reqCtx = iamauth.WithActiveScope(reqCtx, claims.ActiveScopeID, claims.ActiveScopeKey, claims.ActiveScopeType)
	ctx.SetContext(reqCtx)

	// 2) 重新从数据源获取最新有效 RBAC（过滤软删/非激活角色，避免沿用旧 token 快照）
	authSnapshot, err := ar.userService.GetAuthSnapshot(reqCtx, claims.UserID)
	if err != nil {
		return err
	}

	newToken, err := iammw.GenerateTokenWithScope(
		authSnapshot.UserID,
		authSnapshot.TenantID,
		authSnapshot.Username,
		authSnapshot.Roles,
		authSnapshot.Permissions,
		authSnapshot.ActiveScopeID,
		authSnapshot.ActiveScopeKey,
		authSnapshot.ActiveScopeType,
		ar.authConfig.SecretKey,
		ar.authConfig.AccessTokenTTL,
	)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"token": newToken,
	})
}

// forgotPassword 处理forgot密码。
func (ar *AuthRoutes) forgotPassword(ctx httpx.IContext) error {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"message": "If the email exists, reset instructions have been sent.",
	})
}

// resetPassword 重置密码。
func (ar *AuthRoutes) resetPassword(ctx httpx.IContext) error {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"message": "Password reset request accepted.",
	})
}
