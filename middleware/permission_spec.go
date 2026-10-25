package middleware

import "gochen-iam/permissions"

// 权限契约由 permissions 持有；此处保留现有 HTTP 调用方的 API。
type Resource = permissions.Resource
type Action = permissions.Action
type ScopeType = permissions.ScopeType
type RiskLevel = permissions.RiskLevel
type PermissionSpec = permissions.PermissionSpec
type PermissionSet = permissions.PermissionSet

const (
	ResourceAny       = permissions.ResourceAny
	ResourceAdmin     = permissions.ResourceAdmin
	ResourceUser      = permissions.ResourceUser
	ResourceRole      = permissions.ResourceRole
	ResourceGroup     = permissions.ResourceGroup
	ResourceTenant    = permissions.ResourceTenant
	ResourceMenu      = permissions.ResourceMenu
	ResourceSystem    = permissions.ResourceSystem
	ResourceTask      = permissions.ResourceTask
	ResourcePoints    = permissions.ResourcePoints
	ResourceLevel     = permissions.ResourceLevel
	ResourcePlan      = permissions.ResourcePlan
	ResourceFamily    = permissions.ResourceFamily
	ResourceStory     = permissions.ResourceStory
	ResourceMCP       = permissions.ResourceMCP
	ActionAny         = permissions.ActionAny
	ActionRead        = permissions.ActionRead
	ActionList        = permissions.ActionList
	ActionWrite       = permissions.ActionWrite
	ActionDelete      = permissions.ActionDelete
	ActionPublish     = permissions.ActionPublish
	ActionActivate    = permissions.ActionActivate
	ActionManage      = permissions.ActionManage
	ActionAdmin       = permissions.ActionAdmin
	ActionView        = permissions.ActionView
	ActionInvoke      = permissions.ActionInvoke
	ActionSelfRead    = permissions.ActionSelfRead
	ActionSelfEdit    = permissions.ActionSelfEdit
	ScopePlatform     = permissions.ScopePlatform
	ScopeTenant       = permissions.ScopeTenant
	RiskLevelLow      = permissions.RiskLevelLow
	RiskLevelMedium   = permissions.RiskLevelMedium
	RiskLevelHigh     = permissions.RiskLevelHigh
	RiskLevelCritical = permissions.RiskLevelCritical
)

func NewPermissionSet(specs ...PermissionSpec) PermissionSet {
	return permissions.NewPermissionSet(specs...)
}

func NewAPIPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return permissions.NewAPIPermissionSet(resource, actions...)
}

func NewMenuPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return permissions.NewMenuPermissionSet(resource, actions...)
}

func NewActionPermissionSet(resource Resource, actions ...Action) PermissionSet {
	return permissions.NewActionPermissionSet(resource, actions...)
}

func APIPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissions.APIPermissions(resource, actions...)
}

func MenuPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissions.MenuPermissions(resource, actions...)
}

func ActionPermissions(resource Resource, actions ...Action) []PermissionSpec {
	return permissions.ActionPermissions(resource, actions...)
}

func ApiPermission(resource Resource, action Action) PermissionSpec {
	return permissions.ApiPermission(resource, action)
}

func MenuPermission(resource Resource, action Action) PermissionSpec {
	return permissions.MenuPermission(resource, action)
}

func ActionPermission(resource Resource, action Action) PermissionSpec {
	return permissions.ActionPermission(resource, action)
}

func PermissionCode(code string) PermissionSpec {
	return permissions.PermissionCode(code)
}

func JoinActions(groups ...[]Action) []Action {
	return permissions.JoinActions(groups...)
}

func ReadWriteDeleteActions() []Action {
	return permissions.ReadWriteDeleteActions()
}

func ReadWriteActions() []Action {
	return permissions.ReadWriteActions()
}

func ManageActions() []Action {
	return permissions.ManageActions()
}

func SelfActions() []Action {
	return permissions.SelfActions()
}

func JoinPermissionSpecs(groups ...[]PermissionSpec) []PermissionSpec {
	return permissions.JoinPermissionSpecs(groups...)
}

func PermissionByAction(specs []PermissionSpec, action Action) PermissionSpec {
	return permissions.PermissionByAction(specs, action)
}

func PermissionCodes(specs ...PermissionSpec) []string {
	return permissions.PermissionCodes(specs...)
}

func PermissionDefinitions(specs ...PermissionSpec) []PermissionDefinition {
	return permissions.PermissionDefinitions(specs...)
}
