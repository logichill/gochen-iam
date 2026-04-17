package service

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	"gochen/authz"
)

// InstallIAMPermissionCatalog 安装 IAM 严格权限目录。
func InstallIAMPermissionCatalog() error {
	if err := authz.InstallModuleCatalogSync(SyncRequiredPermissionCatalog); err != nil {
		return err
	}
	iammw.RegisterRequiredPermissionDefinitions(IAMPermissionDefinitions...)
	return iammw.ValidateStrictPermissionRegistry()
}

// IAMAuthzPermissionDefinitions 返回 IAM 模块声明的核心权限目录元数据。
func IAMAuthzPermissionDefinitions() []authz.PermissionDefinition {
	return iammw.AuthzPermissionDefinitions(IAMPermissionDefinitions...)
}

// SyncRequiredPermissionCatalog 将模块权限目录同步到 strict permission registry。
func SyncRequiredPermissionCatalog(reg authz.ModuleRegistration) error {
	if len(reg.PermissionDefinitions) > 0 {
		iammw.RegisterRequiredPermissionDefinitions(iammw.PermissionDefinitionsFromAuthz(reg.PermissionDefinitions...)...)
		return nil
	}
	if len(reg.Permissions) == 0 {
		return nil
	}
	iammw.RegisterRequiredPermissions(reg.Permissions...)
	return nil
}

// IAMResourceResolvers 返回 IAM 模块声明的资源解析器目录。
func IAMResourceResolvers() []authz.ITypedResourceResolver {
	return []authz.ITypedResourceResolver{
		authz.TypedResourceResolver[*iamentity.User](func(target *iamentity.User) (authz.Resource, bool) {
			return resourceFromEntity(UserResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Group](func(target *iamentity.Group) (authz.Resource, bool) {
			return resourceFromEntity(GroupResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Role](func(target *iamentity.Role) (authz.Resource, bool) {
			return resourceFromEntity(RoleResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Tenant](func(target *iamentity.Tenant) (authz.Resource, bool) {
			return platformResourceFromEntity(TenantResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.MenuItem](func(target *iamentity.MenuItem) (authz.Resource, bool) {
			return platformResourceFromEntity(MenuResourceKind, target)
		}),
	}
}

// IAMAuthzRegistration 返回 IAM 模块声明的 authz 目录。
func IAMAuthzRegistration() authz.ModuleRegistration {
	return authz.ModuleRegistration{
		ModuleID:              "iam",
		ModuleName:            "IAM",
		Permissions:           append([]string(nil), IAMPermissions...),
		PermissionDefinitions: IAMAuthzPermissionDefinitions(),
		ResourceResolvers:     IAMResourceResolvers(),
	}
}

// NewIAMAuthzRegistry 创建已注册 IAM 目录的 authz 注册表。
func NewIAMAuthzRegistry() (*authz.Registry, error) {
	registry := authz.NewRegistry()
	if err := registry.RegisterModule(IAMAuthzRegistration()); err != nil {
		return nil, err
	}
	return registry, nil
}
