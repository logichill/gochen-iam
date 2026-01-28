package middleware

import (
	"os"

	"gochen/runtime/errorx"
)

const envStrictPermissionRegistry = "AUTH_STRICT_PERMISSION_REGISTRY"

// IsStrictPermissionRegistryEnabled 返回是否启用“严格权限字典”模式。
// 仅在启动期校验 registry 是否已完成加载；运行期不再做“registry 为空则跳过”的 fail-open 逻辑。
func IsStrictPermissionRegistryEnabled() bool {
	v := os.Getenv(envStrictPermissionRegistry)
	return v == "true" || v == "1"
}

// ValidateStrictPermissionRegistryLoaded 在严格模式下校验权限 registry 已完成加载。
// 建议在应用启动、路由装配完成后调用（否则 registry 为空会被误判为“未加载”）。
func ValidateStrictPermissionRegistryLoaded() error {
	if !IsStrictPermissionRegistryEnabled() {
		return nil
	}
	if len(RequiredPermissions()) == 0 {
		return errorx.NewError(errorx.Internal, "AUTH_STRICT_PERMISSION_REGISTRY 已启用但 required permissions registry 为空")
	}
	return nil
}
