package service

import (
	"testing"

	iammw "gochen-iam/middleware"
	auth "gochen-runtime/host/authz"
)

func TestSyncRequiredPermissionCatalog_RegistersDefinitionMetadata(t *testing.T) {
	const permissionCode = "modulecatalogsynctest:api:write"

	if err := SyncRequiredPermissionCatalog(auth.ModuleRegistration{
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
	}); err != nil {
		t.Fatalf("SyncRequiredPermissionCatalog: %v", err)
	}

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

func TestSyncRequiredPermissionCatalog_RegistersPermissionCodesWithoutDefinitions(t *testing.T) {
	const permissionCode = "modulecodesynctest:api:read"

	if err := SyncRequiredPermissionCatalog(auth.ModuleRegistration{
		ModuleID:    "code-sync-test",
		ModuleName:  "Code Sync Test",
		Permissions: []string{permissionCode},
	}); err != nil {
		t.Fatalf("SyncRequiredPermissionCatalog: %v", err)
	}

	if !iammw.HasRequiredPermission(permissionCode) {
		t.Fatalf("expected permission %q to be recognized by strict registry", permissionCode)
	}
}

// TestInstallIAMPermissionCatalog_RegistersCatalogAndMirrorsModules 覆盖生产装配路径：
// IAM 自身目录进入 strict registry，且后续模块经 Catalog 声明的权限自动镜像进来。
func TestInstallIAMPermissionCatalog_RegistersCatalogAndMirrorsModules(t *testing.T) {
	registry := auth.NewRegistry()
	if err := InstallIAMPermissionCatalog(registry); err != nil {
		t.Fatalf("InstallIAMPermissionCatalog: %v", err)
	}

	// IAM 自身目录：路由中间件不会登记 read 码，必须由目录登记覆盖。
	iamReadCode := UserPermissionSet.Code(iammw.ActionRead)
	if !iammw.HasRequiredPermission(iamReadCode) {
		t.Fatalf("expected IAM catalog permission %q in strict registry", iamReadCode)
	}
	// 内置通配定义需带 BuiltinOnly 元数据，供自定义角色校验拒绝复用。
	wildcard := findRequiredPermissionDefinition(iammw.RequiredPermissionDefinitions(), "*:menu:view")
	if wildcard.Code != "*:menu:view" || !wildcard.BuiltinOnly {
		t.Fatalf("expected builtin-only menu visibility wildcard in strict registry, got %#v", wildcard)
	}

	const downstreamCode = "downstreamcatalogtest.designer:menu:view"
	registration := auth.ModuleRegistration{
		ModuleID:   "downstream-catalog-test",
		ModuleName: "Downstream Catalog Test",
		PermissionDefinitions: []auth.PermissionDefinition{
			{
				Code:        downstreamCode,
				Name:        "Downstream Designer Menu",
				Description: "downstream module menu visibility permission",
				Scopes:      []string{string(iammw.ScopePlatform), string(iammw.ScopeTenant)},
			},
		},
	}
	if err := registry.RegisterModule(registration); err != nil {
		t.Fatalf("RegisterModule: %v", err)
	}
	if err := registry.SyncModuleCatalog(registration); err != nil {
		t.Fatalf("SyncModuleCatalog: %v", err)
	}

	got := findRequiredPermissionDefinition(iammw.RequiredPermissionDefinitions(), downstreamCode)
	if got.Code != downstreamCode {
		t.Fatalf("expected downstream permission %q mirrored into strict registry, got %#v", downstreamCode, got)
	}
	if got.Name != "Downstream Designer Menu" {
		t.Fatalf("unexpected mirrored permission metadata: %#v", got)
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
