package middleware

import (
	"gochen-iam/auth"
	httpx "gochen/httpx"
	hbasic "gochen/httpx/nethttp"
	"gochen/runtime/errorx"
)

// RoleMiddleware 角色验证中间件
func RoleMiddleware(requiredRole string) httpx.Middleware {
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.GetContext()
		if reqCtx == nil || reqCtx.GetUserID() == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "用户未认证",
				Role:     requiredRole,
			})
			return errorx.NewError(errorx.Unauthorized, "用户未认证")
		}

		if err := RequireAnyRole(reqCtx, requiredRole); err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "缺少所需角色",
				Role:     requiredRole,
			})
			return err
		}
		return next()
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
			return errorx.NewError(errorx.Internal, "invalid permission definition")
		}
	}

	registerRequiredPermission(requiredPermission)

	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.GetContext()
		if reqCtx == nil || reqCtx.GetUserID() == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "用户未认证",
				Permission: requiredPermission,
			})
			return errorx.NewError(errorx.Unauthorized, "用户未认证")
		}

		if err := RequirePermission(reqCtx, requiredPermission); err != nil {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "权限不足",
				Permission: requiredPermission,
			})
			return err
		}
		return next()
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
			return errorx.NewError(errorx.Unauthorized, "用户未认证")
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
