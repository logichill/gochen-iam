package middleware

import (
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
)

type requiredPermissionMeta struct {
	Callsite string
}

var requiredPermissionsRegistry = struct {
	mu    sync.RWMutex
	perms map[string][]requiredPermissionMeta
}{
	perms: map[string][]requiredPermissionMeta{},
}

func requiredPermissionsCount() int {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	return len(requiredPermissionsRegistry.perms)
}

func registerRequiredPermission(permission string) {
	if permission == "" {
		return
	}

	callsite := "unknown"
	// caller: PermissionMiddleware(...) 的调用点
	_, file, line, ok := runtime.Caller(2)
	if ok {
		callsite = file + ":" + strconv.Itoa(line)
	}

	requiredPermissionsRegistry.mu.Lock()
	defer requiredPermissionsRegistry.mu.Unlock()
	requiredPermissionsRegistry.perms[permission] = append(requiredPermissionsRegistry.perms[permission], requiredPermissionMeta{
		Callsite: callsite,
	})
}

// RequiredPermissions 返回当前进程在启动期间注册到 PermissionMiddleware 的权限集合（去重、排序）。
func RequiredPermissions() []string {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()

	out := make([]string, 0, len(requiredPermissionsRegistry.perms))
	for perm := range requiredPermissionsRegistry.perms {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

// RequiredPermissionsWithCallsites 返回权限及其注册点（用于排查“权限从哪来”）。
func RequiredPermissionsWithCallsites() map[string][]string {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()

	out := make(map[string][]string, len(requiredPermissionsRegistry.perms))
	for perm, metas := range requiredPermissionsRegistry.perms {
		callsites := make([]string, 0, len(metas))
		for _, m := range metas {
			callsites = append(callsites, m.Callsite)
		}
		sort.Strings(callsites)
		out[perm] = callsites
	}
	return out
}

// RequiredPermissionsWithRedactedCallsites 返回权限及其注册点（脱敏：仅保留文件名与行号）。
func RequiredPermissionsWithRedactedCallsites() map[string][]string {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()

	out := make(map[string][]string, len(requiredPermissionsRegistry.perms))
	for perm, metas := range requiredPermissionsRegistry.perms {
		callsites := make([]string, 0, len(metas))
		for _, m := range metas {
			callsites = append(callsites, redactCallsite(m.Callsite))
		}
		sort.Strings(callsites)
		out[perm] = callsites
	}
	return out
}

// RegisterRequiredPermissions 允许模块在启动期一次性注册“系统已声明的权限”集合。
//
// 说明：
// - 严格权限字典模式下，角色写入/校验会基于该 registry 做 fail-close；
// - 该函数用于不依赖路由装配细节也能完成权限字典初始化（例如权限常量集中定义的场景）。
func RegisterRequiredPermissions(permissions ...string) {
	for _, p := range permissions {
		registerRequiredPermission(p)
	}
}

// HasRequiredPermission 判断权限是否已在启动期注册到 required permissions registry。
func HasRequiredPermission(permission string) bool {
	if permission == "" {
		return false
	}
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	_, ok := requiredPermissionsRegistry.perms[permission]
	return ok
}

func redactCallsite(callsite string) string {
	if callsite == "" || callsite == "unknown" {
		return "unknown"
	}
	// 兼容不同路径分隔符（Unix/Windows），保留 "file.go:123"。
	file, line := splitCallsite(callsite)
	base := filepath.Base(file)
	if line == "" {
		return base
	}
	return base + ":" + line
}

func splitCallsite(callsite string) (file string, line string) {
	// callsite 形如 "/abs/path/file.go:123" 或 "file.go:123"。
	for i := len(callsite) - 1; i >= 0; i-- {
		if callsite[i] == ':' {
			return callsite[:i], callsite[i+1:]
		}
	}
	return callsite, ""
}

func resetRequiredPermissionsRegistryForTest() {
	requiredPermissionsRegistry.mu.Lock()
	defer requiredPermissionsRegistry.mu.Unlock()
	requiredPermissionsRegistry.perms = map[string][]requiredPermissionMeta{}
}
