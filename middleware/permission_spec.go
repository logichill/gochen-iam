package middleware

import auth "gochen/auth"

type Resource string

type Action = auth.PermissionAction
type ScopeType = auth.PermissionScope
type RiskLevel = auth.PermissionRisk
type PermissionSpec = auth.PermissionSpec
type PermissionSet = auth.PermissionSet

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

	ActionAny      Action = auth.PermissionActionAny
	ActionRead     Action = auth.PermissionActionRead
	ActionList     Action = auth.PermissionActionList
	ActionWrite    Action = auth.PermissionActionWrite
	ActionDelete   Action = auth.PermissionActionDelete
	ActionPublish  Action = auth.PermissionActionPublish
	ActionActivate Action = auth.PermissionActionActivate
	ActionManage   Action = auth.PermissionActionManage
	ActionAdmin    Action = auth.PermissionActionAdmin
	ActionView     Action = auth.PermissionActionView
	ActionInvoke   Action = auth.PermissionActionInvoke
	ActionSelfRead Action = auth.PermissionActionSelfRead
	ActionSelfEdit Action = auth.PermissionActionSelfEdit

	ScopePlatform ScopeType = auth.PermissionScopePlatform
	ScopeTenant   ScopeType = auth.PermissionScopeTenant

	RiskLevelLow      RiskLevel = auth.PermissionRiskLow
	RiskLevelMedium   RiskLevel = auth.PermissionRiskMedium
	RiskLevelHigh     RiskLevel = auth.PermissionRiskHigh
	RiskLevelCritical RiskLevel = auth.PermissionRiskCritical
)

func NewPermissionSet(specs ...PermissionSpec) PermissionSet {
	return auth.NewPermissionSet(specs...)
}

func NewAPIPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return auth.NewAPIPermissionSet(string(resource), actions...)
}

func NewMenuPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return auth.NewMenuPermissionSet(string(resource), actions...)
}

func NewActionPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return auth.NewActionPermissionSet(string(resource), actions...)
}

func APIPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return auth.APIPermissions(string(resource), actions...)
}

func MenuPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return auth.MenuPermissions(string(resource), actions...)
}

func ActionPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return auth.ActionPermissions(string(resource), actions...)
}

func ApiPermission(resource Resource, action Action) PermissionSpec {
	return auth.APIPermission(string(resource), action)
}

func MenuPermission(resource Resource, action Action) PermissionSpec {
	return auth.MenuPermission(string(resource), action)
}

func ActionPermission(resource Resource, action Action) PermissionSpec {
	return auth.ActionPermission(string(resource), action)
}

func PermissionCode(code string) PermissionSpec {
	return auth.PermissionCode(code)
}

func JoinActions(groups ...[]Action) []Action {
	return auth.JoinActions(groups...)
}

func ReadWriteDeleteActions() []Action {
	return auth.ReadWriteDeleteActions()
}

func ReadWriteActions() []Action {
	return auth.ReadWriteActions()
}

func ManageActions() []Action {
	return auth.ManageActions()
}

func SelfActions() []Action {
	return auth.SelfActions()
}

func JoinPermissionSpecs(groups ...[]PermissionSpec) []PermissionSpec {
	return auth.JoinPermissionSpecs(groups...)
}

func PermissionByAction(specs []PermissionSpec, action Action) PermissionSpec {
	return auth.PermissionByAction(specs, action)
}

func PermissionCodes(specs ...PermissionSpec) []string {
	return auth.PermissionCodesFromSpecs(specs...)
}

func PermissionDefinitions(specs ...PermissionSpec) []PermissionDefinition {
	return PermissionDefinitionsFromAuthz(auth.PermissionDefinitions(specs...)...)
}
