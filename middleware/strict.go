package middleware

import (
	"os"
	"sync/atomic"

	"gochen/runtime/errorx"
)

const envStrictPermissionRegistry = "AUTH_STRICT_PERMISSION_REGISTRY"

var strictRegistryValidated uint32

// IsStrictPermissionRegistryEnabled 返回是否启用“严格权限字典”模式。
// 仅在启动期校验 registry 是否已完成加载；运行期不再做“registry 为空则跳过”的 fail-open 逻辑。
func IsStrictPermissionRegistryEnabled() bool {
	v := os.Getenv(envStrictPermissionRegistry)
	return v == "true" || v == "1"
}

// ValidateStrictPermissionRegistry 在严格模式下校验权限 registry 已完成加载。
func ValidateStrictPermissionRegistry() error {
	if !IsStrictPermissionRegistryEnabled() {
		return nil
	}
	if requiredPermissionsCount() == 0 {
		return errorx.NewError(errorx.Internal, "AUTH_STRICT_PERMISSION_REGISTRY 已启用但 required permissions registry 为空")
	}
	return nil
}

// ValidateStrictPermissionRegistryLoaded 在严格模式下校验权限 registry 已完成加载。
// 建议在应用启动、路由装配完成后调用（否则 registry 为空会被误判为“未加载”）。
//
// Deprecated: use ValidateStrictPermissionRegistry instead.
func ValidateStrictPermissionRegistryLoaded() error {
	return ValidateStrictPermissionRegistry()
}

// EnsureStrictPermissionRegistryLoaded 在严格模式下做一次性校验（缓存结果）。
//
// 说明：
// - 该函数适合在运行期（每个请求入口）做兜底 fail-close；
// - 仅缓存“成功”结果，避免首次调用过早导致把错误永久缓存。
func EnsureStrictPermissionRegistryLoaded() error {
	if !IsStrictPermissionRegistryEnabled() {
		return nil
	}
	if atomic.LoadUint32(&strictRegistryValidated) == 1 {
		return nil
	}
	if err := ValidateStrictPermissionRegistry(); err != nil {
		return err
	}
	atomic.StoreUint32(&strictRegistryValidated, 1)
	return nil
}
