package middleware

import (
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type requiredPermissionMeta struct {
	Callsite string
}

// PermissionType 定义权限类型枚举。
type PermissionType string

const (
	PermissionTypeAPI    PermissionType = "api"
	PermissionTypeMenu   PermissionType = "menu"
	PermissionTypeAction PermissionType = "action"
)

// PermissionDefinition 定义权限Definition。
type PermissionDefinition struct {
	Code        string         `json:"code"`
	Type        PermissionType `json:"type"`
	Resource    string         `json:"resource,omitempty"`
	Action      string         `json:"action,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
}

type registeredPermission struct {
	definition PermissionDefinition
	metas      []requiredPermissionMeta
}

var requiredPermissionsRegistry = struct {
	mu    sync.RWMutex
	perms map[string]registeredPermission
}{
	perms: map[string]registeredPermission{},
}

// requiredPermissionsCount 处理required权限集合Count。
func requiredPermissionsCount() int {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	return len(requiredPermissionsRegistry.perms)
}

// normalizePermissionDefinition 规范化权限Definition。
func normalizePermissionDefinition(def PermissionDefinition) PermissionDefinition {
	def.Code = strings.ToLower(strings.TrimSpace(def.Code))
	if def.Code == "" || !IsValidPermissionCode(def.Code) {
		return PermissionDefinition{}
	}

	segments := strings.Split(def.Code, ":")
	def.Type = PermissionType(segments[0])
	def.Resource = segments[1]
	def.Action = segments[2]
	return def
}

// mergePermissionDefinition 合并权限Definition。
func mergePermissionDefinition(current PermissionDefinition, incoming PermissionDefinition) PermissionDefinition {
	if current.Code == "" {
		return incoming
	}
	if incoming.Type != "" {
		current.Type = incoming.Type
	}
	if incoming.Resource != "" {
		current.Resource = incoming.Resource
	}
	if incoming.Action != "" {
		current.Action = incoming.Action
	}
	if incoming.Name != "" {
		current.Name = incoming.Name
	}
	if incoming.Description != "" {
		current.Description = incoming.Description
	}
	return current
}

// registerRequiredPermission 注册Required权限。
func registerRequiredPermission(def PermissionDefinition) {
	def = normalizePermissionDefinition(def)
	if def.Code == "" {
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
	current := requiredPermissionsRegistry.perms[def.Code]
	current.definition = mergePermissionDefinition(current.definition, def)
	current.metas = append(current.metas, requiredPermissionMeta{
		Callsite: callsite,
	})
	requiredPermissionsRegistry.perms[def.Code] = current
}

// RequiredPermissions 处理Required权限集合。
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
	for perm, entry := range requiredPermissionsRegistry.perms {
		callsites := make([]string, 0, len(entry.metas))
		for _, m := range entry.metas {
			callsites = append(callsites, m.Callsite)
		}
		sort.Strings(callsites)
		out[perm] = callsites
	}
	return out
}

// RequiredPermissionsWithRedactedCallsites 处理Required权限集合并带RedactedCallsites。
func RequiredPermissionsWithRedactedCallsites() map[string][]string {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()

	out := make(map[string][]string, len(requiredPermissionsRegistry.perms))
	for perm, entry := range requiredPermissionsRegistry.perms {
		callsites := make([]string, 0, len(entry.metas))
		for _, m := range entry.metas {
			callsites = append(callsites, redactCallsite(m.Callsite))
		}
		sort.Strings(callsites)
		out[perm] = callsites
	}
	return out
}

// RegisterRequiredPermissionDefinitions 注册Required权限Definitions。
func RegisterRequiredPermissionDefinitions(definitions ...PermissionDefinition) {
	for _, def := range definitions {
		registerRequiredPermission(def)
	}
}

// RegisterRequiredPermissions 允许模块在启动期一次性注册“系统已声明的权限”集合。
//
// 说明：
// - 严格权限字典模式下，角色写入/校验会基于该 registry 做 fail-close；
// - 该函数用于不依赖路由装配细节也能完成权限字典初始化（例如权限常量集中定义的场景）。
func RegisterRequiredPermissions(permissions ...string) {
	for _, p := range permissions {
		registerRequiredPermission(PermissionDefinition{Code: p})
	}
}

// RequiredPermissionDefinitions 处理Required权限Definitions。
func RequiredPermissionDefinitions() []PermissionDefinition {
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()

	out := make([]PermissionDefinition, 0, len(requiredPermissionsRegistry.perms))
	for _, entry := range requiredPermissionsRegistry.perms {
		out = append(out, entry.definition)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Code < out[j].Code
	})
	return out
}

// HasRequiredPermission 判断权限是否已在启动期注册到 required permissions registry。
func HasRequiredPermission(permission string) bool {
	if permission == "" {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(permission))
	if !IsValidPermissionCode(normalized) {
		return false
	}
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	if _, ok := requiredPermissionsRegistry.perms[normalized]; ok {
		return true
	}
	for registered := range requiredPermissionsRegistry.perms {
		if PermissionPatternMatches(normalized, registered) || PermissionPatternMatches(registered, normalized) {
			return true
		}
	}
	return false
}

// redactCallsite 处理redactCallsite。
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

// splitCallsite 处理splitCallsite。
func splitCallsite(callsite string) (file string, line string) {
	// callsite 形如 "/abs/path/file.go:123" 或 "file.go:123"。
	for i := len(callsite) - 1; i >= 0; i-- {
		if callsite[i] == ':' {
			return callsite[:i], callsite[i+1:]
		}
	}
	return callsite, ""
}

// resetRequiredPermissionsRegistryForTest 重置测试Required权限集合注册表。
func resetRequiredPermissionsRegistryForTest() {
	requiredPermissionsRegistry.mu.Lock()
	defer requiredPermissionsRegistry.mu.Unlock()
	requiredPermissionsRegistry.perms = map[string]registeredPermission{}
}
