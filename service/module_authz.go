package service

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	auth "gochen/auth"
)

// InstallIAMPermissionCatalog 安装 IAM 严格权限目录。
func InstallIAMPermissionCatalog() error {
	if err := auth.InstallModuleCatalogSync(SyncRequiredPermissionCatalog); err != nil {
		return err
	}
	iammw.RegisterRequiredPermissionDefinitions(IAMPermissionDefinitions...)
	return iammw.ValidateStrictPermissionRegistry()
}

// IAMAuthzPermissionDefinitions 返回 IAM 模块声明的核心权限目录元数据。
func IAMAuthzPermissionDefinitions() []auth.PermissionDefinition {
	return iammw.AuthzPermissionDefinitions(IAMPermissionDefinitions...)
}

// SyncRequiredPermissionCatalog 将模块权限目录同步到 strict permission registry。
func SyncRequiredPermissionCatalog(reg auth.ModuleRegistration) error {
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
func IAMResourceResolvers() []auth.ITypedResourceResolver {
	return []auth.ITypedResourceResolver{
		auth.TypedResourceResolver[*iamentity.User](func(target *iamentity.User) (auth.Resource, bool) {
			return resourceFromEntity(UserResourceKind, target)
		}),
		auth.TypedResourceResolver[*iamentity.Group](func(target *iamentity.Group) (auth.Resource, bool) {
			return resourceFromEntity(GroupResourceKind, target)
		}),
		auth.TypedResourceResolver[*iamentity.Role](func(target *iamentity.Role) (auth.Resource, bool) {
			return resourceFromEntity(RoleResourceKind, target)
		}),
		auth.TypedResourceResolver[*iamentity.Tenant](func(target *iamentity.Tenant) (auth.Resource, bool) {
			return platformResourceFromEntity(TenantResourceKind, target)
		}),
		auth.TypedResourceResolver[*iamentity.MenuItem](func(target *iamentity.MenuItem) (auth.Resource, bool) {
			return platformResourceFromEntity(MenuResourceKind, target)
		}),
	}
}

// IAMAuthzRegistration 返回 IAM 模块声明的 authz 目录。
func IAMAuthzRegistration() auth.ModuleRegistration {
	return auth.ModuleRegistration{
		ModuleID:              "iam",
		ModuleName:            "IAM",
		Permissions:           append([]string(nil), IAMPermissions...),
		PermissionDefinitions: IAMAuthzPermissionDefinitions(),
		ResourceResolvers:     IAMResourceResolvers(),
	}
}

// NewIAMAuthzRegistry 创建已注册 IAM 目录的 authz 注册表。
func NewIAMAuthzRegistry() (*auth.Registry, error) {
	registry := auth.NewRegistry()
	if err := registry.RegisterModule(IAMAuthzRegistration()); err != nil {
		return nil, err
	}
	return registry, nil
}
