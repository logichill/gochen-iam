package middleware

import (
	"gochen/errors"
)

// ValidateStrictPermissionRegistry 校验权限 registry 已完成加载（fail-close）。
func ValidateStrictPermissionRegistry() error {
	requiredPermissionsRegistry.mu.RLock()
	registryErr := requiredPermissionsRegistry.err
	requiredPermissionsRegistry.mu.RUnlock()
	if registryErr != nil {
		return registryErr
	}
	if requiredPermissionsCount() == 0 {
		return errors.NewCode(errors.Internal, "required permissions registry 为空（尚未完成权限字典注册）").
			WithContext("hint", "请确保启动期已执行权限注册：要么在路由装配时使用 PermissionMiddleware(PermissionCode(\"api:resource:action\")) 或 PermissionMiddleware(ApiPermission(...))，要么在模块启动期调用 RegisterRequiredPermissionDefinitions(...) 或 RegisterRequiredPermissions(...)；随后在装配完成后调用 ValidateStrictPermissionRegistry() 进行 fail-close 校验。")
	}
	return nil
}

// EnsureStrictPermissionRegistryLoaded 做运行期 fail-close 校验。
//
// 实现只读 registry 的 map 长度与 err 字段，开销很小；不做一次性缓存，
// 以便测试/热加载时清空 registry 后立刻被检测到。
func EnsureStrictPermissionRegistryLoaded() error {
	return ValidateStrictPermissionRegistry()
}
