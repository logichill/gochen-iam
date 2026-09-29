package router

import (
	"context"
	"strings"
	"time"

	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	"gochen-iam/tenant"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
)

// AuthRoutes 认证路由注册器
type AuthRoutes struct {
	userService IUserService
	authConfig  *iammw.AuthConfig
}

// NewAuthRoutesWithConfig 使用统一认证配置创建认证路由注册器。
func NewAuthRoutesWithConfig(userService IUserService, config *iammw.AuthConfig) *AuthRoutes {
	return &AuthRoutes{
		userService: userService,
		authConfig:  config,
	}
}

func authRequestContext(ctx httpx.IContext) context.Context {
	if ctx == nil {
		return context.Background()
	}
	if reqCtx := ctx.RequestContext(); reqCtx != nil {
		return reqCtx
	}
	return context.Background()
}

// RegisterRoutes 注册路由。
func (ar *AuthRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if ar.authConfig == nil {
		return errors.NewCode(errors.InvalidInput, "auth config is required")
	}
	authGroup := group.Group("/auth")

	authGroup.POST("/register", ar.register)
	authGroup.POST("/login", ar.login)
	authGroup.GET("/csrf", ar.csrfToken)
	authGroup.POST("/activate-scope", ar.activateScope)
	authGroup.POST("/logout", ar.logout)
	authGroup.POST("/refresh", ar.refreshToken)
	authGroup.POST("/forgot-password", ar.forgotPassword)
	authGroup.POST("/reset-password", ar.resetPassword)
	return nil
}

func (ar *AuthRoutes) csrfToken(ctx httpx.IContext) error {
	token := iammw.EnsureCSRFCookie(ctx, ar.authConfig)
	if token == "" {
		return errors.NewCode(errors.Unsupported, "cookie authentication is disabled")
	}
	return httpx.WriteSuccess(ctx, map[string]string{"csrf_token": token})
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
		return ""
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
		return reqCtx, "", errors.NewCode(errors.InvalidInput, "auth config is required")
	}
	tenantID, err := tenant.ResolveRequestTenantIDWithPolicy(cfg.TenantPolicy, ar.readRequestTenantID(ctx), currentTenantID, cfg.RequireTenant)
	if err != nil {
		return reqCtx, "", err
	}
	if tenantID == "" || currentTenantID == tenantID {
		return reqCtx.WithContext(tenant.WithPolicy(reqCtx, cfg.TenantPolicy)), tenantID, nil
	}
	derived, err := contextx.WithTenantID(reqCtx, tenantID)
	if err != nil {
		return reqCtx, "", err
	}
	reqCtx = reqCtx.WithContext(derived)
	reqCtx = reqCtx.WithContext(tenant.WithPolicy(reqCtx, cfg.TenantPolicy))
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
	reqCtx, _, err := ar.ensureTenantContext(ctx)
	if err != nil {
		return err
	}
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

	session, err := ar.userService.ActivateScope(reqCtx, claims.UserID, req.ScopeID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(claims.BindingVersion) != "" && claims.BindingVersion != session.BindingVersion {
		return errors.NewCode(errors.Forbidden, "授权绑定已变化，请重新登录")
	}

	token, err := iammw.GenerateTokenWithTTL(
		session.UserID,
		session.ActiveScopeID,
		session.BindingVersion,
		session.Permissions,
		ar.authConfig.SecretKey,
		ar.authConfig.AccessTokenTTL,
	)
	if err != nil {
		return err
	}
	iammw.WriteAccessTokenCookie(ctx, token, ar.authConfig)
	iammw.WriteCSRFCookie(ctx, ar.authConfig)

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
	token := iammw.ExtractAccessToken(ctx, ar.authConfig)
	if token != "" {
		claims, err := iammw.ValidateAccessToken(authRequestContext(ctx), token, ar.authConfig)
		if err != nil {
			if !errors.Is(err, errors.Unauthorized) {
				return err
			}
		} else {
			if err := iammw.EnforceCSRFDoubleSubmit(ctx, ar.authConfig); err != nil {
				return err
			}
			if strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil {
				return errors.NewCode(errors.Unauthorized, "token 不支持安全退出")
			}
			if err := iammw.RevokeAccessTokenJTI(authRequestContext(ctx), ar.authConfig, claims.ID, claims.ExpiresAt.Time); err != nil {
				return err
			}
		}
	}
	iammw.ClearAccessTokenCookie(ctx, ar.authConfig)
	iammw.ClearCSRFCookie(ctx, ar.authConfig)
	return httpx.WriteSuccess(ctx, map[string]interface{}{
		"message": "logged_out",
	})
}

// refreshToken 处理refresh令牌。
func (ar *AuthRoutes) refreshToken(ctx httpx.IContext) error {
	var req struct {
		Token string `json:"token"`
	}
	// Body token is optional when the HttpOnly access cookie is present.
	_ = ctx.BindJSON(&req)
	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = iammw.ExtractAccessToken(ctx, ar.authConfig)
	}
	if token == "" {
		return errors.NewCode(errors.Validation, "token is required")
	}

	// 1) 验证旧 token
	claims, err := iammw.ValidateAccessToken(authRequestContext(ctx), token, ar.authConfig)
	if err != nil {
		return err
	}
	if strings.TrimSpace(claims.ID) == "" || claims.ExpiresAt == nil {
		return errors.NewCode(errors.Unauthorized, "token 不支持安全轮转")
	}

	reqCtx, tenantID, err := ar.ensureTenantContext(ctx)
	if err != nil {
		return err
	}
	reqCtx, err = iammw.InjectClaimsRequestContext(reqCtx, tenantID, claims, ar.authConfig.ContextResolver)
	if err != nil {
		return err
	}
	ctx.SetContext(reqCtx)

	authSnapshot, err := ar.userService.AuthSnapshot(reqCtx, claims.UserID, claims.ActiveScopeID)
	if err != nil {
		return err
	}

	newToken, err := iammw.GenerateTokenWithTTL(
		authSnapshot.UserID,
		authSnapshot.ActiveScopeID,
		authSnapshot.BindingVersion,
		authSnapshot.Permissions,
		ar.authConfig.SecretKey,
		ar.authConfig.AccessTokenTTL,
	)
	if err != nil {
		return err
	}
	// 在吊销旧 token 前再次校验，避免快照读取期间已被其他请求轮转。
	claims, err = iammw.ValidateAccessToken(authRequestContext(ctx), token, ar.authConfig)
	if err != nil {
		return err
	}
	consumed, err := iammw.ConsumeAccessTokenJTI(authRequestContext(ctx), ar.authConfig, claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		return err
	}
	if !consumed {
		return errors.NewCode(errors.Unauthorized, "token 已被轮转")
	}
	iammw.WriteAccessTokenCookie(ctx, newToken, ar.authConfig)
	iammw.WriteCSRFCookie(ctx, ar.authConfig)

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
