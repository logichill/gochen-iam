package middleware

import (
	"regexp"
	"strings"

	"gochen-iam/auth"
	"gochen/errorx"
	"gochen/httpx"
)

var permissionCodePattern = regexp.MustCompile(`^(\*|[A-Za-z0-9_]+):(\*|[A-Za-z0-9_.]+):(\*|[A-Za-z0-9_]+)$`)

// IsValidPermissionCode 用于校验权限码格式（命名治理的最小护栏）。
func IsValidPermissionCode(permission string) bool {
	if len(permission) == 0 || len(permission) > 128 {
		return false
	}
	return permissionCodePattern.MatchString(permission)
}

// PermissionPatternMatches 判断 pattern 是否命中 permission。
//
// 约定：
// - 仅支持“整段通配” `*`，不支持正则或半段模糊；
// - `pattern` 可为 `api:task:*`、`api:*:*`、`*:*:*` 等；
// - `permission` 通常应是具体权限，但也允许传入合法的三段式通配符。
func PermissionPatternMatches(pattern string, permission string) bool {
	patternSegments, ok := permissionSegments(pattern)
	if !ok {
		return false
	}
	permissionSegments, ok := permissionSegments(permission)
	if !ok {
		return false
	}

	for i := range patternSegments {
		if patternSegments[i] == "*" {
			continue
		}
		if patternSegments[i] != permissionSegments[i] {
			return false
		}
	}
	return true
}

// permissionSegments 处理权限Segments。
func permissionSegments(permission string) ([3]string, bool) {
	var segments [3]string
	normalized := strings.ToLower(strings.TrimSpace(permission))
	if !IsValidPermissionCode(normalized) {
		return segments, false
	}
	parts := strings.Split(normalized, ":")
	if len(parts) != len(segments) {
		return segments, false
	}
	copy(segments[:], parts)
	return segments, true
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
	if set := auth.GetPermissionSet(ctx); set != nil {
		normalized := strings.ToLower(permission)
		if _, ok := set[normalized]; ok {
			return true
		}
	}
	perms := GetPermissions(ctx)
	if len(perms) == 0 {
		return false
	}
	for _, p := range perms {
		if PermissionPatternMatches(p, permission) {
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
