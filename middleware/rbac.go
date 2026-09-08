package middleware

import (
	"strings"

	iamauth "gochen-iam/auth"
	auth "gochen-runtime/host/authz"
	"gochen/auth/action"
	"gochen/errors"
	"gochen/httpx"
)

// IsValidPermissionCode 用于校验权限码格式（命名治理的最小护栏）。
func IsValidPermissionCode(permission string) bool {
	return action.IsValidCode(permission)
}

// Roles 从请求上下文中获取当前请求的角色列表
func Roles(ctx httpx.IRequestContext) []string {
	return iamauth.Roles(ctx)
}

// Permissions 从请求上下文中获取当前请求的权限列表
func Permissions(ctx httpx.IRequestContext) []string {
	return iamauth.Permissions(ctx)
}

// HasAnyRole 判断上下文中是否包含任一指定角色
func HasAnyRole(ctx httpx.IRequestContext, required ...string) bool {
	if len(required) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	roles := Roles(ctx)
	if len(roles) == 0 {
		return false
	}
	for _, need := range required {
		need = strings.TrimSpace(need)
		if need == "" {
			continue
		}
		for _, r := range roles {
			r = strings.TrimSpace(r)
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
	return errors.NewCode(errors.Forbidden, "无访问权限")
}

// HasPermission 判断是否拥有指定权限
func HasPermission(ctx httpx.IRequestContext, permission string) bool {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return false
	}
	if principal, ok := auth.PrincipalFromContext(ctx); ok && principal.AllowsPermission(permission) {
		return true
	}
	if set := iamauth.PermissionSet(ctx); set != nil {
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
		if action.PatternMatches(p, permission) {
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
	return errors.NewCode(errors.Forbidden, "权限不足")
}
