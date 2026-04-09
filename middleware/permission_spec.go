package middleware

import (
	"fmt"
	"strings"
)

type Resource string
type Action string
type ScopeType string

const (
	ResourceAny    Resource = "*"
	ResourceAdmin  Resource = "admin"
	ResourceUser   Resource = "user"
	ResourceRole   Resource = "role"
	ResourceGroup  Resource = "group"
	ResourceTenant Resource = "tenant"
	ResourceMenu   Resource = "menu"
	ResourceSystem Resource = "system"

	ActionAny      Action = "*"
	ActionRead     Action = "read"
	ActionList     Action = "list"
	ActionWrite    Action = "write"
	ActionDelete   Action = "delete"
	ActionPublish  Action = "publish"
	ActionActivate Action = "activate"
	ActionManage   Action = "manage"
	ActionSelfRead Action = "read_self"
	ActionSelfEdit Action = "update_self"

	ScopePlatform ScopeType = "platform"
	ScopeTenant   ScopeType = "tenant"
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
