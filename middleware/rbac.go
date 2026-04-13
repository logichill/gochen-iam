package middleware

import (
	"strings"

	"gochen-iam/auth"
	"gochen/authz"
	"gochen/errorx"
	"gochen/httpx"
)

// IsValidPermissionCode 用于校验权限码格式（命名治理的最小护栏）。
func IsValidPermissionCode(permission string) bool {
	return authz.IsValidPermissionCode(permission)
}

// Roles 从请求上下文中获取当前请求的角色列表
func Roles(ctx httpx.IRequestContext) []string {
	return auth.Roles(ctx)
}

// Permissions 从请求上下文中获取当前请求的权限列表
func Permissions(ctx httpx.IRequestContext) []string {
	return auth.Permissions(ctx)
}

// HasAnyRole 判断上下文中是否包含任一指定角色
func HasAnyRole(ctx httpx.IRequestContext, required ...string) bool {
	if len(required) == 0 {
		return true
	}
	roles := Roles(ctx)
	if len(roles) == 0 {
		return false
	}
	for _, need := range required {
		for _, r := range roles {
			if strings.EqualFold(r, need) {
				return true
			}
		}
	}
	return false
}

// RequireAnyRole 处理要求Any角色。
func RequireAnyRole(ctx httpx.IRequestContext, required ...string) error {
	if HasAnyRole(ctx, required...) {
		return nil
	}
	return errorx.New(errorx.Forbidden, "无访问权限")
}

// HasPermission 判断是否拥有指定权限
func HasPermission(ctx httpx.IRequestContext, permission string) bool {
	if permission == "" {
		return true
	}
	if principal, ok := authz.PrincipalFromContext(ctx); ok && principal.AllowsPermission(permission) {
		return true
	}
	if set := auth.PermissionSet(ctx); set != nil {
		normalized := strings.ToLower(permission)
		if _, ok := set[normalized]; ok {
			return true
		}
	}
	perms := Permissions(ctx)
	if len(perms) == 0 {
		return false
	}
	for _, p := range perms {
		if authz.PermissionPatternMatches(p, permission) {
			return true
		}
	}
	return false
}

// RequirePermission 处理要求权限。
func RequirePermission(ctx httpx.IRequestContext, permission string) error {
	if HasPermission(ctx, permission) {
		return nil
	}
	return errorx.New(errorx.Forbidden, "权限不足")
}
