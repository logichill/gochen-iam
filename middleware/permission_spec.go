package middleware

import (
	"fmt"
	"strings"
)

type Resource string
type Action string
type ScopeType string
type RiskLevel string

const (
	ResourceAny    Resource = "*"
	ResourceAdmin  Resource = "admin"
	ResourceUser   Resource = "user"
	ResourceRole   Resource = "role"
	ResourceGroup  Resource = "group"
	ResourceTenant Resource = "tenant"
	ResourceMenu   Resource = "menu"
	ResourceSystem Resource = "system"
	ResourceTask   Resource = "task"
	ResourcePoints Resource = "points"
	ResourceLevel  Resource = "level"
	ResourcePlan   Resource = "plan"
	ResourceFamily Resource = "family"
	ResourceStory  Resource = "story"
	ResourceMCP    Resource = "mcp"

	ActionAny      Action = "*"
	ActionRead     Action = "read"
	ActionList     Action = "list"
	ActionWrite    Action = "write"
	ActionDelete   Action = "delete"
	ActionPublish  Action = "publish"
	ActionActivate Action = "activate"
	ActionManage   Action = "manage"
	ActionAdmin    Action = "admin"
	ActionView     Action = "view"
	ActionInvoke   Action = "invoke"
	ActionSelfRead Action = "read_self"
	ActionSelfEdit Action = "update_self"

	ScopePlatform ScopeType = "platform"
	ScopeTenant   ScopeType = "tenant"

	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

type PermissionSpec struct {
	Code        string         `json:"code"`
	Type        PermissionType `json:"type"`
	Resource    Resource       `json:"resource,omitempty"`
	Action      Action         `json:"action,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Scopes      []ScopeType    `json:"scopes,omitempty"`
	BuiltinOnly bool           `json:"builtin_only,omitempty"`
	RiskLevel   string         `json:"risk_level,omitempty"`
}

type PermissionSet struct {
	specs    []PermissionSpec
	byAction map[Action]PermissionSpec
}

func NewPermissionSet(specs ...PermissionSpec) PermissionSet {
	specs = JoinPermissionSpecs(specs)
	set := PermissionSet{
		specs:    append([]PermissionSpec(nil), specs...),
		byAction: make(map[Action]PermissionSpec, len(specs)),
	}
	for _, spec := range specs {
		action := Action(strings.TrimSpace(string(spec.Action)))
		if action == "" {
			continue
		}
		set.byAction[action] = spec
	}
	return set
}

func NewAPIPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return NewPermissionSet(APIPermissions(resource, actions...)...)
}

func NewMenuPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return NewPermissionSet(MenuPermissions(resource, actions...)...)
}

func NewActionPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return NewPermissionSet(ActionPermissions(resource, actions...)...)
}

func APIPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissionSpecs(PermissionTypeAPI, resource, actions...)
}

func MenuPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissionSpecs(PermissionTypeMenu, resource, actions...)
}

func ActionPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissionSpecs(PermissionTypeAction, resource, actions...)
}

func ApiPermission(resource Resource, action Action) PermissionSpec {
	return permissionSpec(PermissionTypeAPI, resource, action)
}

func MenuPermission(resource Resource, action Action) PermissionSpec {
	return permissionSpec(PermissionTypeMenu, resource, action)
}

func ActionPermission(resource Resource, action Action) PermissionSpec {
	return permissionSpec(PermissionTypeAction, resource, action)
}

func PermissionCode(code string) PermissionSpec {
	code = strings.ToLower(strings.TrimSpace(code))
	spec := PermissionSpec{Code: code}
	if !IsValidPermissionCode(code) {
		return spec
	}
	segments := strings.Split(code, ":")
	spec.Type = PermissionType(segments[0])
	spec.Resource = Resource(segments[1])
	spec.Action = Action(segments[2])
	return spec
}

func (s PermissionSet) Specs() []PermissionSpec {
	return append([]PermissionSpec(nil), s.specs...)
}

func (s PermissionSet) Codes() []string {
	return PermissionCodes(s.specs...)
}

func (s PermissionSet) Definitions() []PermissionDefinition {
	return PermissionDefinitions(s.specs...)
}

func (s PermissionSet) Find(action Action) (PermissionSpec, bool) {
	action = Action(strings.TrimSpace(string(action)))
	if action == "" {
		return PermissionSpec{}, false
	}
	spec, ok := s.byAction[action]
	return spec, ok
}

func (s PermissionSet) Must(action Action) PermissionSpec {
	spec, ok := s.Find(action)
	if !ok {
		return PermissionSpec{}
	}
	return spec
}

func (s PermissionSet) Code(action Action) string {
	return s.Must(action).Code
}

func JoinActions(groups ...[]Action) []Action {
	if len(groups) == 0 {
		return nil
	}
	actions := make([]Action, 0)
	for _, group := range groups {
		actions = append(actions, group...)
	}
	return normalizeActions(actions)
}

func ReadWriteDeleteActions() []Action {
	return []Action{ActionRead, ActionWrite, ActionDelete}
}

func ReadWriteActions() []Action {
	return []Action{ActionRead, ActionWrite}
}

func ManageActions() []Action {
	return []Action{ActionManage, ActionRead, ActionWrite, ActionDelete}
}

func SelfActions() []Action {
	return []Action{ActionSelfRead, ActionSelfEdit}
}

func JoinPermissionSpecs(groups ...[]PermissionSpec) []PermissionSpec {
	if len(groups) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]PermissionSpec, 0)
	for _, group := range groups {
		for _, spec := range group {
			code := strings.TrimSpace(spec.Code)
			if code == "" {
				continue
			}
			if _, ok := seen[code]; ok {
				continue
			}
			seen[code] = struct{}{}
			out = append(out, spec)
		}
	}
	return out
}

func PermissionByAction(specs []PermissionSpec, action Action) PermissionSpec {
	action = Action(strings.TrimSpace(string(action)))
	for _, spec := range specs {
		if spec.Action == action {
			return spec
		}
	}
	return PermissionSpec{}
}

func PermissionCodes(specs ...PermissionSpec) []string {
	if len(specs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(specs))
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		code := strings.ToLower(strings.TrimSpace(spec.Code))
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	return out
}

func PermissionDefinitions(specs ...PermissionSpec) []PermissionDefinition {
	if len(specs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(specs))
	out := make([]PermissionDefinition, 0, len(specs))
	for _, spec := range specs {
		code := strings.ToLower(strings.TrimSpace(spec.Code))
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, spec.Definition())
	}
	return out
}

func permissionSpecs(permissionType PermissionType, resource Resource, actions ...Action) []PermissionSpec {
	actions = normalizeActions(actions)
	if len(actions) == 0 {
		return nil
	}
	specs := make([]PermissionSpec, 0, len(actions))
	for _, action := range actions {
		specs = append(specs, permissionSpec(permissionType, resource, action))
	}
	return specs
}

func permissionSpec(permissionType PermissionType, resource Resource, action Action) PermissionSpec {
	spec := PermissionSpec{
		Type:     permissionType,
		Resource: resource,
		Action:   action,
	}
	if resource != "" && action != "" {
		spec.Code = fmt.Sprintf("%s:%s:%s", permissionType, resource, action)
	}
	return spec
}

func normalizeActions(actions []Action) []Action {
	if len(actions) == 0 {
		return nil
	}
	seen := make(map[Action]struct{}, len(actions))
	out := make([]Action, 0, len(actions))
	for _, action := range actions {
		action = Action(strings.TrimSpace(string(action)))
		if action == "" {
			continue
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		out = append(out, action)
	}
	return out
}

func (p PermissionSpec) Desc(description string) PermissionSpec {
	p.Description = strings.TrimSpace(description)
	return p
}

func (p PermissionSpec) Label(name string) PermissionSpec {
	p.Name = strings.TrimSpace(name)
	return p
}

func (p PermissionSpec) Scope(scopes ...ScopeType) PermissionSpec {
	if len(scopes) == 0 {
		p.Scopes = nil
		return p
	}
	seen := make(map[ScopeType]struct{}, len(scopes))
	p.Scopes = p.Scopes[:0]
	for _, scope := range scopes {
		scope = ScopeType(strings.TrimSpace(string(scope)))
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		p.Scopes = append(p.Scopes, scope)
	}
	return p
}

func (p PermissionSpec) Builtin() PermissionSpec {
	p.BuiltinOnly = true
	return p
}

func (p PermissionSpec) Risk(level RiskLevel) PermissionSpec {
	p.RiskLevel = strings.TrimSpace(string(level))
	return p
}

func (p PermissionSpec) Definition() PermissionDefinition {
	def := PermissionDefinition{
		Code:        strings.ToLower(strings.TrimSpace(p.Code)),
		Type:        p.Type,
		Resource:    string(p.Resource),
		Action:      string(p.Action),
		Name:        p.Name,
		Description: p.Description,
		BuiltinOnly: p.BuiltinOnly,
		RiskLevel:   p.RiskLevel,
	}
	if len(p.Scopes) > 0 {
		def.Scopes = make([]string, 0, len(p.Scopes))
		for _, scope := range p.Scopes {
			if normalized := strings.TrimSpace(string(scope)); normalized != "" {
				def.Scopes = append(def.Scopes, normalized)
			}
		}
	}
	return def
}
