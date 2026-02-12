package middleware

import (
	"gochen-iam/auth"
	"gochen/errorx"
	"gochen/httpx"
	hbasic "gochen/httpx/nethttp"
)

type permissionChecker struct{}

func (permissionChecker) HasPermission(ctx httpx.IContext, permission string) bool {
	if ctx == nil {
		return false
	}
	return HasPermission(ctx.GetContext(), permission)
}

func (permissionChecker) HasAnyPermission(ctx httpx.IContext, permissions []string) bool {
	if len(permissions) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	reqCtx := ctx.GetContext()
	if reqCtx == nil {
		return false
	}
	for _, p := range permissions {
		if HasPermission(reqCtx, p) {
			return true
		}
	}
	return false
}

func (permissionChecker) HasRole(ctx httpx.IContext, role string) bool {
	if ctx == nil {
		return false
	}
	return HasAnyRole(ctx.GetContext(), role)
}

func (permissionChecker) HasAnyRole(ctx httpx.IContext, roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	return HasAnyRole(ctx.GetContext(), roles...)
}

// RoleMiddleware 角色验证中间件
func RoleMiddleware(requiredRole string) httpx.Middleware {
	base := httpx.RoleMiddleware(permissionChecker{}, requiredRole)
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.GetContext()
		if reqCtx == nil || reqCtx.GetUserID() == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "用户未认证",
				Role:     requiredRole,
			})
			return errorx.New(errorx.Unauthorized, "用户未认证")
		}

		called := false
		err := base(ctx, func() error {
			called = true
			return next()
		})
		if err != nil && !called {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "缺少所需角色",
				Role:     requiredRole,
			})
		}
		return err
	}
}

// PermissionMiddleware 权限验证中间件
func PermissionMiddleware(requiredPermission string) httpx.Middleware {
	if !IsValidPermissionCode(requiredPermission) {
		// 这是“装配期配置错误”，直接 fail-close，避免无意间放开保护。
		return func(ctx httpx.IContext, next func() error) error {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "invalid permission definition",
				Permission: requiredPermission,
			})
			return errorx.New(errorx.Internal, "invalid permission definition")
		}
	}

	registerRequiredPermission(requiredPermission)

	base := httpx.PermissionMiddleware(permissionChecker{}, requiredPermission)
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.GetContext()
		if reqCtx == nil || reqCtx.GetUserID() == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "用户未认证",
				Permission: requiredPermission,
			})
			return errorx.New(errorx.Unauthorized, "用户未认证")
		}

		called := false
		err := base(ctx, func() error {
			called = true
			return next()
		})
		if err != nil && !called {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "权限不足",
				Permission: requiredPermission,
			})
		}
		return err
	}
}

// AdminOnlyMiddleware 仅管理员中间件
func AdminOnlyMiddleware() httpx.Middleware {
	return RoleMiddleware("system_admin")
}

// UserOnlyMiddleware 仅用户中间件（已认证用户）
func UserOnlyMiddleware() httpx.Middleware {
	return func(ctx httpx.IContext, next func() error) error {
		userID := ctx.GetContext().GetUserID()
		if userID == 0 {
			return errorx.New(errorx.Unauthorized, "用户未认证")
		}
		return next()
	}
}

// InjectAuthContext 将角色与权限信息注入 IRequestContext，供后续 RBAC 使用。
func InjectAuthContext(reqCtx httpx.IRequestContext, userID int64, roles, permissions []string) httpx.IRequestContext {
	reqCtx = hbasic.WithUserID(reqCtx, userID)
	reqCtx = auth.WithRoles(reqCtx, roles)
	reqCtx = auth.WithPermissions(reqCtx, permissions)
	return reqCtx
}
