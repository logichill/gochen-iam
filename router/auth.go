package router

import (
	"strings"
	"time"

	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	"gochen-iam/tenant"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
	"gochen/httpx/nethttp"
)

// AuthRoutes 认证路由注册器
type AuthRoutes struct {
	userService IUserService
	utils       *nethttp.Utils
	authConfig  *iammw.AuthConfig
}

// NewAuthRoutes 创建认证路由注册器
func NewAuthRoutes(userService IUserService) *AuthRoutes {
	return &AuthRoutes{
		userService: userService,
		utils:       &nethttp.Utils{},
		authConfig:  iammw.DefaultAuthConfig(),
	}
}

// RegisterRoutes 注册路由。
func (ar *AuthRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	authGroup := group.Group("/auth")

	authGroup.POST("/register", ar.register)
	authGroup.POST("/login", ar.login)
	authGroup.POST("/activate-scope", ar.activateScope)
	authGroup.POST("/logout", ar.logout)
	authGroup.POST("/refresh", ar.refreshToken)
	authGroup.POST("/forgot-password", ar.forgotPassword)
	authGroup.POST("/reset-password", ar.resetPassword)
	return nil
}

// Name 获取注册器名称
func (ar *AuthRoutes) Name() string {
	return "auth"
}

// Priority 获取注册优先级
func (ar *AuthRoutes) Priority() int {
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
	currentTenantID := contextx.TenantID(reqCtx)
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
	derived, err := contextx.WithTenantID(reqCtx, tenantID)
	if err != nil {
		return reqCtx, "", err
	}
	reqCtx = reqCtx.WithContext(derived)
	ctx.SetContext(reqCtx)
	return reqCtx, tenantID, nil
}

func (ar *AuthRoutes) authContextResolver() iammw.AuthContextResolver {
	if ar != nil && ar.authConfig != nil && ar.authConfig.ContextResolver != nil {
		return ar.authConfig.ContextResolver
	}
	return iammw.ResolveInstalledAuthContextResolver()
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

	availableScopeIDs := make([]int64, 0, len(authResult.AvailableScopes))
	for _, scope := range authResult.AvailableScopes {
		if scope.ScopeID > 0 {
			availableScopeIDs = append(availableScopeIDs, scope.ScopeID)
		}
	}
	activationToken, err := iammw.GenerateActivationToken(
		authResult.UserID,
		authResult.BindingVersion,
		availableScopeIDs,
		ar.authConfig.SecretKey,
		ar.authConfig.ActivationTTL,
	)
	if err != nil {
		return err
	}

	type loginResponse struct {
		UserID          int64                    `json:"user_id"`
		Username        string                   `json:"username"`
		Email           string                   `json:"email"`
		BindingVersion  string                   `json:"binding_version"`
		ActivationToken string                   `json:"activation_token"`
		ExpiresAt       time.Time                `json:"expires_at"`
		AvailableScopes []iamsvc.AuthScopeOption `json:"available_scopes"`
	}
	resp := &loginResponse{
		UserID:          authResult.UserID,
		Username:        authResult.Username,
		Email:           authResult.Email,
		BindingVersion:  authResult.BindingVersion,
		ActivationToken: activationToken,
		ExpiresAt:       time.Now().Add(ar.authConfig.ActivationTTL),
		AvailableScopes: authResult.AvailableScopes,
	}

	return httpx.WriteSuccess(ctx, resp)
}

func (ar *AuthRoutes) activateScope(ctx httpx.IContext) error {
	var req struct {
		ActivationToken string `json:"activation_token" binding:"required"`
		ScopeID         int64  `json:"scope_id" binding:"required"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}
	claims, err := iammw.ParseActivationToken(req.ActivationToken, ar.authConfig.SecretKey)
	if err != nil {
		return err
	}
	allowed := false
	for _, scopeID := range claims.AvailableScopes {
		if scopeID == req.ScopeID {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.NewCode(errors.Forbidden, "当前认证结果不允许激活目标授权域")
	}

	session, err := ar.userService.ActivateScope(ctx.RequestContext(), claims.UserID, req.ScopeID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(claims.BindingVersion) != "" && claims.BindingVersion != session.BindingVersion {
		return errors.NewCode(errors.Forbidden, "授权绑定已变化，请重新登录")
	}

	token, err := iammw.GenerateToken(
		session.UserID,
		session.ActiveScopeID,
		session.BindingVersion,
		session.Permissions,
		ar.authConfig.SecretKey,
	)
	if err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"user_id":         session.UserID,
		"username":        session.Username,
		"email":           session.Email,
		"active_scope_id": session.ActiveScopeID,
		"binding_version": session.BindingVersion,
		"permissions":     session.Permissions,
		"token":           token,
		"expires_at":      time.Now().Add(ar.authConfig.AccessTokenTTL),
	})
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
		err := errors.NewCode(errors.Validation, "token is required")
		return err
	}

	// 1) 验证旧 token
	claims, err := iammw.ParseToken(req.Token, ar.authConfig.SecretKey)
	if err != nil {
		return err
	}

	reqCtx := ctx.RequestContext()
	tenantID, err := tenant.ResolveRequestTenantID(ar.readRequestTenantID(ctx), contextx.TenantID(reqCtx), ar.authConfig.RequireTenant)
	if err != nil {
		return err
	}
	reqCtx, err = iammw.InjectClaimsRequestContext(reqCtx, tenantID, claims, ar.authContextResolver())
	if err != nil {
		return err
	}
	ctx.SetContext(reqCtx)

	authSnapshot, err := ar.userService.AuthSnapshot(reqCtx, claims.UserID, claims.ActiveScopeID)
	if err != nil {
		return err
	}

	newToken, err := iammw.GenerateToken(
		authSnapshot.UserID,
		authSnapshot.ActiveScopeID,
		authSnapshot.BindingVersion,
		authSnapshot.Permissions,
		ar.authConfig.SecretKey,
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
