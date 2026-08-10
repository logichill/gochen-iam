package middleware

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	auth "gochen/auth"
)

type requiredPermissionMeta struct {
	Callsite string
}

// PermissionType 复用核心 authz 权限类型。
type PermissionType = auth.PermissionType

const (
	PermissionTypeAPI    PermissionType = auth.PermissionTypeAPI
	PermissionTypeMenu   PermissionType = auth.PermissionTypeMenu
	PermissionTypeAction PermissionType = auth.PermissionTypeAction
)

// PermissionDefinition 直接复用核心 authz 权限 definition。
type PermissionDefinition = auth.PermissionDefinition

// AuthzPermissionDefinitions 批量将 IAM 权限 definition 转换为核心 authz definition。
func AuthzPermissionDefinitions(definitions ...PermissionDefinition) []auth.PermissionDefinition {
	if len(definitions) == 0 {
		return nil
	}
	return append([]auth.PermissionDefinition(nil), definitions...)
}

// PermissionDefinitionFromAuthz 将核心 authz definition 转换为 IAM 权限 definition。
func PermissionDefinitionFromAuthz(definition auth.PermissionDefinition) PermissionDefinition {
	return PermissionDefinition(definition)
}

// PermissionDefinitionsFromAuthz 批量将核心 authz definition 转换为 IAM 权限 definition。
func PermissionDefinitionsFromAuthz(definitions ...auth.PermissionDefinition) []PermissionDefinition {
	if len(definitions) == 0 {
		return nil
	}
	return append([]PermissionDefinition(nil), definitions...)
}

type registeredPermission struct {
	definition PermissionDefinition
	metas      []requiredPermissionMeta
}

var requiredPermissionsRegistry = struct {
	mu    sync.RWMutex
	perms map[string]registeredPermission
	err   error
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
	if def.Code == "" {
		return PermissionDefinition{}
	}
	if IsValidPermissionCode(def.Code) {
		segments := strings.Split(def.Code, ":")
		def.Type = segments[0]
		def.Resource = segments[1]
		def.Action = segments[2]
	} else {
		def.Type = strings.TrimSpace(def.Type)
		def.Resource = strings.TrimSpace(def.Resource)
		def.Action = strings.TrimSpace(def.Action)
	}
	def.Name = strings.TrimSpace(def.Name)
	def.Description = strings.TrimSpace(def.Description)
	def.RiskLevel = strings.ToLower(strings.TrimSpace(def.RiskLevel))
	if len(def.Scopes) > 0 {
		scopes := make([]string, 0, len(def.Scopes))
		seen := make(map[string]struct{}, len(def.Scopes))
		for _, scope := range def.Scopes {
			scope = strings.ToLower(strings.TrimSpace(scope))
			if scope == "" {
				continue
			}
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		def.Scopes = scopes
	}
	return def
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func permissionDefinitionConflict(current PermissionDefinition, incoming PermissionDefinition) string {
	if current.Code == "" || incoming.Code == "" || current.Code != incoming.Code {
		return ""
	}
	if current.Type != "" && incoming.Type != "" && current.Type != incoming.Type {
		return fmt.Sprintf("type mismatch: %s vs %s", current.Type, incoming.Type)
	}
	if current.Resource != "" && incoming.Resource != "" && current.Resource != incoming.Resource {
		return fmt.Sprintf("resource mismatch: %s vs %s", current.Resource, incoming.Resource)
	}
	if current.Action != "" && incoming.Action != "" && current.Action != incoming.Action {
		return fmt.Sprintf("action mismatch: %s vs %s", current.Action, incoming.Action)
	}
	if current.Name != "" && incoming.Name != "" && current.Name != incoming.Name {
		return fmt.Sprintf("name mismatch: %q vs %q", current.Name, incoming.Name)
	}
	if current.Description != "" && incoming.Description != "" && current.Description != incoming.Description {
		return fmt.Sprintf("description mismatch: %q vs %q", current.Description, incoming.Description)
	}
	if len(current.Scopes) > 0 && len(incoming.Scopes) > 0 && !sameStringSlice(current.Scopes, incoming.Scopes) {
		return fmt.Sprintf("scopes mismatch: %v vs %v", current.Scopes, incoming.Scopes)
	}
	if current.RiskLevel != "" && incoming.RiskLevel != "" && current.RiskLevel != incoming.RiskLevel {
		return fmt.Sprintf("risk_level mismatch: %s vs %s", current.RiskLevel, incoming.RiskLevel)
	}
	return ""
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
	if len(incoming.Scopes) > 0 {
		current.Scopes = append([]string(nil), incoming.Scopes...)
	}
	if incoming.BuiltinOnly {
		current.BuiltinOnly = true
	}
	if incoming.RiskLevel != "" {
		current.RiskLevel = incoming.RiskLevel
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
	if conflict := permissionDefinitionConflict(current.definition, def); conflict != "" && requiredPermissionsRegistry.err == nil {
		requiredPermissionsRegistry.err = fmt.Errorf(
			"required permission definition conflict for %s: %s (existing: %s, incoming: %s)",
			def.Code,
			conflict,
			strings.Join(redactMetas(current.metas), ", "),
			redactCallsite(callsite),
		)
	}
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

func requiredPermissionDefinition(code string) (PermissionDefinition, bool) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if normalized == "" {
		return PermissionDefinition{}, false
	}
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	entry, ok := requiredPermissionsRegistry.perms[normalized]
	if !ok {
		return PermissionDefinition{}, false
	}
	return entry.definition, true
}

// HasRequiredPermission 判断权限是否已在启动期注册到 required permissions registry。
func HasRequiredPermission(permission string) bool {
	if permission == "" {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(permission))
	requiredPermissionsRegistry.mu.RLock()
	defer requiredPermissionsRegistry.mu.RUnlock()
	if _, ok := requiredPermissionsRegistry.perms[normalized]; ok {
		return true
	}
	if !IsValidPermissionCode(normalized) {
		return false
	}
	for registered := range requiredPermissionsRegistry.perms {
		if !IsValidPermissionCode(registered) {
			continue
		}
		if auth.PermissionPatternMatches(normalized, registered) {
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

func redactMetas(metas []requiredPermissionMeta) []string {
	out := make([]string, 0, len(metas))
	for _, meta := range metas {
		out = append(out, redactCallsite(meta.Callsite))
	}
	sort.Strings(out)
	return out
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
	requiredPermissionsRegistry.err = nil
}
