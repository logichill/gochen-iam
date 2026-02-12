package middleware

import (
	"regexp"
	"strings"

	"gochen-iam/auth"
	"gochen/errorx"
	"gochen/httpx"
)

var permissionCodePattern = regexp.MustCompile(`^[A-Za-z0-9_]+:[A-Za-z0-9_]+$`)

// IsValidPermissionCode 用于校验权限码格式（命名治理的最小护栏）。
func IsValidPermissionCode(permission string) bool {
	if len(permission) == 0 || len(permission) > 128 {
		return false
	}
	return permissionCodePattern.MatchString(permission)
}

// GetRoles 从请求上下文中获取当前请求的角色列表
func GetRoles(ctx httpx.IRequestContext) []string {
	return auth.GetRoles(ctx)
}

// GetPermissions 从请求上下文中获取当前请求的权限列表
func GetPermissions(ctx httpx.IRequestContext) []string {
	return auth.GetPermissions(ctx)
}

// HasAnyRole 判断上下文中是否包含任一指定角色
func HasAnyRole(ctx httpx.IRequestContext, required ...string) bool {
	if len(required) == 0 {
		return true
	}
	roles := GetRoles(ctx)
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

// RequireAnyRole 校验上下文中是否包含任一指定角色,否则返回 Forbidden 错误
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
	// 管理员拥有所有权限
	if HasAnyRole(ctx, "system_admin") {
		return true
	}
	if set := auth.GetPermissionSet(ctx); set != nil {
		_, ok := set[strings.ToLower(permission)]
		return ok
	}
	perms := GetPermissions(ctx)
	if len(perms) == 0 {
		return false
	}
	for _, p := range perms {
		if strings.EqualFold(p, permission) {
			return true
		}
	}
	return false
}

// RequirePermission 校验是否拥有指定权限,否则返回 Forbidden 错误
func RequirePermission(ctx httpx.IRequestContext, permission string) error {
	if HasPermission(ctx, permission) {
		return nil
	}
	return errorx.New(errorx.Forbidden, "权限不足")
}
