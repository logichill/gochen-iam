package middleware

import (
	"sync/atomic"

	"gochen/errorx"
)

var strictRegistryValidated uint32

// ValidateStrictPermissionRegistry 校验权限 registry 已完成加载（fail-close）。
func ValidateStrictPermissionRegistry() error {
	if requiredPermissionsCount() == 0 {
		return errorx.New(errorx.Internal, "required permissions registry 为空（尚未完成权限字典注册）").
			WithContext("hint", "请确保启动期已执行权限注册：要么在路由装配时使用 PermissionMiddleware(\"x:y\")，要么在模块启动期调用 RegisterRequiredPermissions(...)；随后在装配完成后调用 ValidateStrictPermissionRegistry() 进行 fail-close 校验。")
	}
	return nil
}

// EnsureStrictPermissionRegistryLoaded 做一次性校验（缓存结果）。
//
// 说明：
// - 该函数适合在运行期（每个请求入口）做兜底 fail-close；
// - 仅缓存“成功”结果，避免首次调用过早导致把错误永久缓存。
func EnsureStrictPermissionRegistryLoaded() error {
	if atomic.LoadUint32(&strictRegistryValidated) == 1 {
		return nil
	}
	if err := ValidateStrictPermissionRegistry(); err != nil {
		return err
	}
	atomic.StoreUint32(&strictRegistryValidated, 1)
	return nil
}
