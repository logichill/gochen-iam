package service

import (
	"testing"

	iammw "gochen-iam/middleware"
	auth "gochen/auth/core"
)

func TestSyncRequiredPermissionCatalog_RegistersDefinitionMetadata(t *testing.T) {
	const permissionCode = "api:modulecatalogsynctest:write"

	SyncRequiredPermissionCatalog(auth.ModuleRegistration{
		ModuleID:   "sync-test",
		ModuleName: "Sync Test",
		PermissionDefinitions: []auth.PermissionDefinition{
			{
				Code:        permissionCode,
				Name:        "Module Catalog Sync Test",
				Description: "ensure module definitions reach strict registry",
				Scopes:      []string{"tenant"},
				BuiltinOnly: true,
				RiskLevel:   "high",
			},
		},
	})

	got := findRequiredPermissionDefinition(iammw.RequiredPermissionDefinitions(), permissionCode)
	if got.Code != permissionCode {
		t.Fatalf("expected required permission %q to be registered, got %#v", permissionCode, got)
	}
	if got.Type != string(iammw.PermissionTypeAPI) || got.Resource != "modulecatalogsynctest" || got.Action != string(iammw.ActionWrite) {
		t.Fatalf("expected normalized type/resource/action, got %#v", got)
	}
	if got.Name != "Module Catalog Sync Test" || got.Description != "ensure module definitions reach strict registry" {
		t.Fatalf("unexpected required permission metadata: %#v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != string(iammw.ScopeTenant) || !got.BuiltinOnly || got.RiskLevel != string(iammw.RiskLevelHigh) {
		t.Fatalf("unexpected required permission policy metadata: %#v", got)
	}
}

func TestSyncRequiredPermissionCatalog_RegistersExternalPermissionCode(t *testing.T) {
	const permissionCode = "ems.reporting.write"

	SyncRequiredPermissionCatalog(auth.ModuleRegistration{
		ModuleID:   "reporting",
		ModuleName: "Reporting",
		PermissionDefinitions: []auth.PermissionDefinition{
			{
				Code:        permissionCode,
				Name:        "Reporting Write",
				Description: "allow mutate reporting resources",
				Scopes:      []string{"tenant"},
				RiskLevel:   "high",
			},
		},
	})

	if !iammw.HasRequiredPermission(permissionCode) {
		t.Fatalf("expected external permission %q to be recognized by strict registry", permissionCode)
	}
	got := findRequiredPermissionDefinition(iammw.RequiredPermissionDefinitions(), permissionCode)
	if got.Code != permissionCode {
		t.Fatalf("expected required permission %q to be registered, got %#v", permissionCode, got)
	}
	if got.Type != "" || got.Resource != "" || got.Action != "" {
		t.Fatalf("expected external permission to keep empty type/resource/action, got %#v", got)
	}
	if got.Name != "Reporting Write" || got.Description != "allow mutate reporting resources" {
		t.Fatalf("unexpected external permission metadata: %#v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != string(iammw.ScopeTenant) || got.RiskLevel != string(iammw.RiskLevelHigh) {
		t.Fatalf("unexpected external permission policy metadata: %#v", got)
	}
}

func findRequiredPermissionDefinition(definitions []iammw.PermissionDefinition, code string) iammw.PermissionDefinition {
	for _, definition := range definitions {
		if definition.Code == code {
			return definition
		}
	}
	return iammw.PermissionDefinition{}
}
