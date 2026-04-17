package middleware

import "gochen/authz"

type Resource string

type Action = authz.PermissionAction
type ScopeType = authz.PermissionScope
type RiskLevel = authz.PermissionRisk

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

	ActionAny      Action = authz.PermissionActionAny
	ActionRead     Action = authz.PermissionActionRead
	ActionList     Action = authz.PermissionActionList
	ActionWrite    Action = authz.PermissionActionWrite
	ActionDelete   Action = authz.PermissionActionDelete
	ActionPublish  Action = authz.PermissionActionPublish
	ActionActivate Action = authz.PermissionActionActivate
	ActionManage   Action = authz.PermissionActionManage
	ActionAdmin    Action = authz.PermissionActionAdmin
	ActionView     Action = authz.PermissionActionView
	ActionInvoke   Action = authz.PermissionActionInvoke
	ActionSelfRead Action = authz.PermissionActionSelfRead
	ActionSelfEdit Action = authz.PermissionActionSelfEdit

	ScopePlatform ScopeType = authz.PermissionScopePlatform
	ScopeTenant   ScopeType = authz.PermissionScopeTenant

	RiskLevelLow      RiskLevel = authz.PermissionRiskLow
	RiskLevelMedium   RiskLevel = authz.PermissionRiskMedium
	RiskLevelHigh     RiskLevel = authz.PermissionRiskHigh
	RiskLevelCritical RiskLevel = authz.PermissionRiskCritical
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
	inner authz.PermissionSet
}

func NewPermissionSet(specs ...PermissionSpec) PermissionSet {
	return PermissionSet{inner: authz.NewPermissionSet(toAuthzPermissionSpecs(specs)...)}
}

func NewAPIPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return PermissionSet{inner: authz.NewAPIPermissionSet(string(resource), toAuthzActions(actions)...)}
}

func NewMenuPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return PermissionSet{inner: authz.NewMenuPermissionSet(string(resource), toAuthzActions(actions)...)}
}

func NewActionPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return PermissionSet{inner: authz.NewActionPermissionSet(string(resource), toAuthzActions(actions)...)}
}

func APIPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return fromAuthzPermissionSpecs(authz.APIPermissions(string(resource), toAuthzActions(actions)...))
}

func MenuPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return fromAuthzPermissionSpecs(authz.MenuPermissions(string(resource), toAuthzActions(actions)...))
}

func ActionPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return fromAuthzPermissionSpecs(authz.ActionPermissions(string(resource), toAuthzActions(actions)...))
}

func ApiPermission(resource Resource, action Action) PermissionSpec {
	return fromAuthzPermissionSpec(authz.APIPermission(string(resource), action))
}

func MenuPermission(resource Resource, action Action) PermissionSpec {
	return fromAuthzPermissionSpec(authz.MenuPermission(string(resource), action))
}

func ActionPermission(resource Resource, action Action) PermissionSpec {
	return fromAuthzPermissionSpec(authz.ActionPermission(string(resource), action))
}

func PermissionCode(code string) PermissionSpec {
	return fromAuthzPermissionSpec(authz.PermissionCode(code))
}

func (s PermissionSet) Specs() []PermissionSpec {
	return fromAuthzPermissionSpecs(s.inner.Specs())
}

func (s PermissionSet) Codes() []string {
	return s.inner.Codes()
}

func (s PermissionSet) Definitions() []PermissionDefinition {
	return PermissionDefinitionsFromAuthz(s.inner.Definitions()...)
}

func (s PermissionSet) Find(action Action) (PermissionSpec, bool) {
	spec, ok := s.inner.Find(action)
	return fromAuthzPermissionSpec(spec), ok
}

func (s PermissionSet) Must(action Action) PermissionSpec {
	return fromAuthzPermissionSpec(s.inner.Must(action))
}

func (s PermissionSet) Code(action Action) string {
	return s.inner.Code(action)
}

func JoinActions(groups ...[]Action) []Action {
	joined := authz.JoinActions(toAuthzActionGroups(groups)...)
	return append([]Action(nil), joined...)
}

func ReadWriteDeleteActions() []Action {
	return append([]Action(nil), authz.ReadWriteDeleteActions()...)
}

func ReadWriteActions() []Action {
	return append([]Action(nil), authz.ReadWriteActions()...)
}

func ManageActions() []Action {
	return append([]Action(nil), authz.ManageActions()...)
}

func SelfActions() []Action {
	return append([]Action(nil), authz.SelfActions()...)
}

func JoinPermissionSpecs(groups ...[]PermissionSpec) []PermissionSpec {
	return fromAuthzPermissionSpecs(authz.JoinPermissionSpecs(toAuthzPermissionSpecGroups(groups)...))
}

func PermissionByAction(specs []PermissionSpec, action Action) PermissionSpec {
	return fromAuthzPermissionSpec(authz.PermissionByAction(toAuthzPermissionSpecs(specs), action))
}

func PermissionCodes(specs ...PermissionSpec) []string {
	return authz.PermissionCodesFromSpecs(toAuthzPermissionSpecs(specs)...)
}

func PermissionDefinitions(specs ...PermissionSpec) []PermissionDefinition {
	return PermissionDefinitionsFromAuthz(authz.PermissionDefinitions(toAuthzPermissionSpecs(specs)...)...)
}

func (p PermissionSpec) Desc(description string) PermissionSpec {
	return fromAuthzPermissionSpec(p.toAuthz().Desc(description))
}

func (p PermissionSpec) Label(name string) PermissionSpec {
	return fromAuthzPermissionSpec(p.toAuthz().Label(name))
}

func (p PermissionSpec) Scope(scopes ...ScopeType) PermissionSpec {
	return fromAuthzPermissionSpec(p.toAuthz().Scope(toAuthzScopes(scopes)...))
}

func (p PermissionSpec) Builtin() PermissionSpec {
	return fromAuthzPermissionSpec(p.toAuthz().Builtin())
}

func (p PermissionSpec) Risk(level RiskLevel) PermissionSpec {
	return fromAuthzPermissionSpec(p.toAuthz().Risk(level))
}

func (p PermissionSpec) Definition() PermissionDefinition {
	return PermissionDefinitionFromAuthz(p.toAuthz().Definition())
}

func (p PermissionSpec) toAuthz() authz.PermissionSpec {
	spec := authz.PermissionSpec{
		Code:        p.Code,
		Type:        authz.PermissionType(p.Type),
		Resource:    string(p.Resource),
		Action:      p.Action,
		Name:        p.Name,
		Description: p.Description,
		BuiltinOnly: p.BuiltinOnly,
		RiskLevel:   p.RiskLevel,
	}
	if len(p.Scopes) > 0 {
		spec.Scopes = toAuthzScopes(p.Scopes)
	}
	return spec
}

func fromAuthzPermissionSpec(spec authz.PermissionSpec) PermissionSpec {
	out := PermissionSpec{
		Code:        spec.Code,
		Type:        PermissionType(spec.Type),
		Resource:    Resource(spec.Resource),
		Action:      Action(spec.Action),
		Name:        spec.Name,
		Description: spec.Description,
		BuiltinOnly: spec.BuiltinOnly,
		RiskLevel:   spec.RiskLevel,
	}
	if len(spec.Scopes) > 0 {
		out.Scopes = fromAuthzScopes(spec.Scopes)
	}
	return out
}

func toAuthzPermissionSpecs(specs []PermissionSpec) []authz.PermissionSpec {
	if len(specs) == 0 {
		return nil
	}
	out := make([]authz.PermissionSpec, 0, len(specs))
	for _, spec := range specs {
		out = append(out, spec.toAuthz())
	}
	return out
}

func fromAuthzPermissionSpecs(specs []authz.PermissionSpec) []PermissionSpec {
	if len(specs) == 0 {
		return nil
	}
	out := make([]PermissionSpec, 0, len(specs))
	for _, spec := range specs {
		out = append(out, fromAuthzPermissionSpec(spec))
	}
	return out
}

func toAuthzPermissionSpecGroups(groups [][]PermissionSpec) [][]authz.PermissionSpec {
	if len(groups) == 0 {
		return nil
	}
	out := make([][]authz.PermissionSpec, 0, len(groups))
	for _, group := range groups {
		out = append(out, toAuthzPermissionSpecs(group))
	}
	return out
}

func toAuthzActions(actions []Action) []authz.PermissionAction {
	if len(actions) == 0 {
		return nil
	}
	return append([]authz.PermissionAction(nil), actions...)
}

func toAuthzActionGroups(groups [][]Action) [][]authz.PermissionAction {
	if len(groups) == 0 {
		return nil
	}
	out := make([][]authz.PermissionAction, 0, len(groups))
	for _, group := range groups {
		out = append(out, toAuthzActions(group))
	}
	return out
}

func toAuthzScopes(scopes []ScopeType) []authz.PermissionScope {
	if len(scopes) == 0 {
		return nil
	}
	return append([]authz.PermissionScope(nil), scopes...)
}

func fromAuthzScopes(scopes []authz.PermissionScope) []ScopeType {
	if len(scopes) == 0 {
		return nil
	}
	return append([]ScopeType(nil), scopes...)
}
