package middleware

import (
	"strings"

	iamauth "gochen-iam/auth"
	"gochen/auth/http"
	"gochen/contextx"
	"gochen/errors"
	"gochen/httpx"
)

type permissionChecker struct{}

// HasPermission 判断权限。
func (permissionChecker) HasPermission(ctx httpx.IContext, permission string) bool {
	if ctx == nil {
		return false
	}
	return HasPermission(ctx.RequestContext(), permission)
}

// HasAnyPermission 判断Any权限。
func (permissionChecker) HasAnyPermission(ctx httpx.IContext, permissions []string) bool {
	if len(permissions) == 0 {
		return false
	}
	if ctx == nil {
		return false
	}
	reqCtx := ctx.RequestContext()
	if reqCtx == nil {
		return false
	}
	for _, p := range permissions {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if HasPermission(reqCtx, p) {
			return true
		}
	}
	return false
}

// HasRole 判断角色。
func (permissionChecker) HasRole(ctx httpx.IContext, role string) bool {
	if ctx == nil {
		return false
	}
	return HasAnyRole(ctx.RequestContext(), role)
}

// HasAnyRole 判断Any角色。
//
// 约定：空角色列表表示调用方未声明角色约束，按 fail-open 处理；
// 空权限列表仍按 fail-closed 处理，避免权限配置缺失时意外放行。
func (permissionChecker) HasAnyRole(ctx httpx.IContext, roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	return HasAnyRole(ctx.RequestContext(), roles...)
}

// RoleMiddleware 角色验证中间件
func RoleMiddleware(requiredRole string) httpx.Middleware {
	base := httpx.RoleMiddleware(permissionChecker{}, requiredRole)
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.RequestContext()
		if reqCtx == nil || GetUserID(reqCtx) == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision: "deny",
				Reason:   "用户未认证",
				Role:     requiredRole,
			})
			return errors.NewCode(errors.Unauthorized, "用户未认证")
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

// PermissionMiddleware 权限验证中间件。
//
// 只接受结构化 PermissionSpec，避免字符串入口静默丢失风险等级等运行时元数据。
func PermissionMiddleware(required PermissionSpec) httpx.Middleware {
	requiredPermission := required.Definition()
	if !IsValidPermissionCode(requiredPermission.Code) {
		// 这是“装配期配置错误”，直接 fail-close，避免无意间放开保护。
		return func(ctx httpx.IContext, next func() error) error {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "invalid permission definition",
				Permission: requiredPermission.Code,
			})
			return errors.NewCode(errors.Internal, "invalid permission definition")
		}
	}

	registerRequiredPermission(requiredPermission)
	if enriched, ok := requiredPermissionDefinition(requiredPermission.Code); ok {
		requiredPermission = mergePermissionDefinition(requiredPermission, enriched)
	}

	base := authhttp.PermissionMiddleware(permissionSpecFromDefinition(requiredPermission))
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.RequestContext()
		if reqCtx == nil || GetUserID(reqCtx) == 0 {
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     "用户未认证",
				Permission: requiredPermission.Code,
			})
			return errors.NewCode(errors.Unauthorized, "用户未认证")
		}

		called := false
		err := base(ctx, func() error {
			called = true
			return next()
		})
		if err != nil && !called {
			reason := "权限不足"
			if errors.Is(err, errors.Unauthorized) {
				reason = "用户未认证"
			}
			recordAuthzDenied(ctx, AuditRecord{
				Decision:   "deny",
				Reason:     reason,
				Permission: requiredPermission.Code,
			})
		}
		return err
	}
}

func permissionSpecFromDefinition(def PermissionDefinition) PermissionSpec {
	spec := PermissionCode(def.Code)
	if def.Name != "" {
		spec = spec.Label(def.Name)
	}
	if def.Description != "" {
		spec = spec.Desc(def.Description)
	}
	if len(def.Scopes) > 0 {
		scopes := make([]ScopeType, 0, len(def.Scopes))
		for _, scope := range def.Scopes {
			scopes = append(scopes, ScopeType(scope))
		}
		spec = spec.Scope(scopes...)
	}
	if def.BuiltinOnly {
		spec = spec.Builtin()
	}
	if def.RiskLevel != "" {
		spec = spec.Risk(RiskLevel(def.RiskLevel))
	}
	return spec
}

// AdminOnlyMiddleware 要求当前 active scope 具备管理员级全量权限。
//
// 这里不再依赖 `system_admin` 角色名，而是依赖角色真正授予出的权限集合；
// 平台管理员与租户管理员都可以通过各自 scope 内的 `*:*:*` 进入对应后台。
func AdminOnlyMiddleware() httpx.Middleware {
	return PermissionMiddleware(
		PermissionCode("*:*:*").
			Desc("管理员入口").
			Scope(ScopePlatform, ScopeTenant).
			Builtin().
			Risk(RiskLevelCritical),
	)
}

// PlatformScopeMiddleware 要求当前 token 的 active scope 是 platform。
func PlatformScopeMiddleware() httpx.Middleware {
	return func(ctx httpx.IContext, next func() error) error {
		reqCtx := ctx.RequestContext()
		if reqCtx == nil || GetUserID(reqCtx) == 0 {
			return errors.NewCode(errors.Unauthorized, "用户未认证")
		}
		if iamauth.ActiveScopeKind(reqCtx) != string(ScopePlatform) {
			return errors.NewCode(errors.Forbidden, "当前授权域不是 platform")
		}
		return next()
	}
}

// UserOnlyMiddleware 仅用户中间件（已认证用户）
func UserOnlyMiddleware() httpx.Middleware {
	return func(ctx httpx.IContext, next func() error) error {
		userID := GetUserID(ctx.RequestContext())
		if userID == 0 {
			return errors.NewCode(errors.Unauthorized, "用户未认证")
		}
		return next()
	}
}

// InjectAuthContext 处理Inject鉴权上下文。
func InjectAuthContext(reqCtx httpx.IRequestContext, userID int64, roles, permissions []string) httpx.IRequestContext {
	derived, err := contextx.WithUserID(reqCtx, userID)
	if err == nil {
		reqCtx = reqCtx.WithContext(derived)
	}
	reqCtx = iamauth.WithRoles(reqCtx, roles)
	reqCtx = iamauth.WithPermissions(reqCtx, permissions)
	return reqCtx
}
