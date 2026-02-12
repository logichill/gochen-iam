package router

import (
	iammw "gochen-iam/middleware"
	iamsvc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	usersvc "gochen-iam/service/user"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

// AuthRoutes 认证路由注册器
type AuthRoutes struct {
	userService  *usersvc.UserService
	groupService *groupsvc.GroupService
	roleService  *rolesvc.RoleService
	utils        *hbasic.Utils
	authConfig   *iammw.AuthConfig
}

// NewAuthRoutes 创建认证路由注册器
func NewAuthRoutes(userService *usersvc.UserService, groupService *groupsvc.GroupService, roleService *rolesvc.RoleService) *AuthRoutes {
	return &AuthRoutes{
		userService:  userService,
		groupService: groupService,
		roleService:  roleService,
		utils:        &hbasic.Utils{},
		authConfig:   iammw.DefaultAuthConfig(),
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

// 认证处理器方法
func (ar *AuthRoutes) register(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	req := &iamsvc.RegisterRequest{}

	if err := ctx.BindJSON(req); err != nil {
		return err
	}

	user, err := ar.userService.Register(reqCtx, req)
	if err != nil {
		return err
	}

	if user != nil {
		user.Password = ""
	}

	ar.utils.WriteSuccessResponse(ctx, user)
	return nil
}

func (ar *AuthRoutes) login(ctx httpx.IContext) error {
	reqCtx := ctx.GetRequest().Context()
	req := &iamsvc.LoginRequest{}

	if err := ctx.BindJSON(req); err != nil {
		return err
	}

	resp, err := ar.userService.Login(reqCtx, req)
	if err != nil {
		return err
	}

	// 基于用户信息生成 JWT，携带角色与权限声明
	roles, err := ar.userService.GetUserRoles(reqCtx, resp.UserID)
	if err != nil {
		return err
	}
	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
	}

	token, err := iammw.GenerateTokenWithTTL(resp.UserID, resp.Username, roleNames, resp.Permissions, ar.authConfig.SecretKey, ar.authConfig.AccessTokenTTL)
	if err != nil {
		return err
	}
	resp.Token = token

	ar.utils.WriteSuccessResponse(ctx, resp)
	return nil
}

func (ar *AuthRoutes) logout(ctx httpx.IContext) error {
	ar.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"message": "logged_out",
	})
	return nil
}

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

	// 2) 重新从数据源获取最新 RBAC（避免 refresh 继续沿用旧 token 快照）
	user, err := ar.userService.GetUserProfile(ctx.GetRequest().Context(), claims.UserID)
	if err != nil {
		return err
	}

	roleNames := make([]string, 0, len(user.Roles))
	for i := range user.Roles {
		roleNames = append(roleNames, user.Roles[i].Name)
	}
	perms := user.GetAllPermissions()

	newToken, err := iammw.GenerateTokenWithTTL(user.GetID(), user.Username, roleNames, perms, ar.authConfig.SecretKey, ar.authConfig.AccessTokenTTL)
	if err != nil {
		return err
	}

	ar.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"token": newToken,
	})
	return nil
}

func (ar *AuthRoutes) forgotPassword(ctx httpx.IContext) error {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}

	ar.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"message": "If the email exists, reset instructions have been sent.",
	})
	return nil
}

func (ar *AuthRoutes) resetPassword(ctx httpx.IContext) error {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}
	if err := ctx.BindJSON(&req); err != nil {
		return err
	}

	ar.utils.WriteSuccessResponse(ctx, map[string]interface{}{
		"message": "Password reset request accepted.",
	})
	return nil
}
