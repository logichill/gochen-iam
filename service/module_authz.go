package service

import (
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/errors"
)

// IModuleCatalogSyncRegistry 表示可安装模块目录同步钩子的 authz 注册表。
//
// 只声明所需的最小能力，避免 IAM 依赖具体 registry 实现。
type IModuleCatalogSyncRegistry interface {
	InstallModuleCatalogSync(auth.ModuleCatalogSyncFunc) error
}

// IAMAuthzPermissionDefinitions 返回 IAM 模块声明的核心权限目录元数据。
func IAMAuthzPermissionDefinitions() []auth.PermissionDefinition {
	return iammw.AuthzPermissionDefinitions(IAMPermissionDefinitions...)
}

// RegisterIAMPermissionCatalog 把 IAM 自身权限目录登记进 strict permission registry。
//
// 说明：strict registry 是角色授权校验（validatePermissions）与权限目录接口的事实源，
// 路由装配期的 PermissionMiddleware 只会登记「路由实际拦截的那几个码」，
// 因此必须由模块显式登记完整目录，否则 read/write/delete 与 menu:view 等码会被判为“未知权限”。
func RegisterIAMPermissionCatalog() {
	iammw.RegisterRequiredPermissionDefinitions(IAMPermissionDefinitions...)
}

// InstallIAMPermissionCatalog 安装 IAM 严格权限目录。
//
// 职责：
//   - 安装模块目录同步钩子：各模块经 Extension(authz.Catalog{...}) 声明的权限
//     自动镜像进 strict registry，无需下游模块重复注册；
//   - 登记 IAM 自身权限目录；
//   - 完成后做一次 fail-close 校验。
//
// 装配位置在应用侧（authz.Registry 由应用创建）：
//
//	registry := authz.NewRegistry()
//	if err := iamservice.InstallIAMPermissionCatalog(registry); err != nil { ... }
//	host.Run(ctx, config.WithCatalogRegistrar(authz.NewCatalogRegistrar(registry)), ...)
func InstallIAMPermissionCatalog(registry IModuleCatalogSyncRegistry) error {
	if registry == nil {
		return errors.NewCode(errors.InvalidInput, "authz registry is nil")
	}
	if err := registry.InstallModuleCatalogSync(SyncRequiredPermissionCatalog); err != nil {
		return err
	}
	RegisterIAMPermissionCatalog()
	return iammw.ValidateStrictPermissionRegistry()
}

// SyncRequiredPermissionCatalog 将模块 authz 目录同步到 strict permission registry。
func SyncRequiredPermissionCatalog(reg auth.ModuleRegistration) error {
	if len(reg.PermissionDefinitions) > 0 {
		iammw.RegisterRequiredPermissionDefinitions(reg.PermissionDefinitions...)
		return nil
	}
	if len(reg.Permissions) == 0 {
		return nil
	}
	iammw.RegisterRequiredPermissions(reg.Permissions...)
	return nil
}

// IAMResourceResolvers 返回 IAM 模块声明的资源解析器目录。
func IAMResourceResolvers() []scoped.ITypedResourceResolver {
	return []scoped.ITypedResourceResolver{
		scoped.TypedResourceResolver[*iamentity.User](func(target *iamentity.User) (scoped.Resource, bool) {
			return resourceFromEntity(UserResourceKind, target)
		}),
		scoped.TypedResourceResolver[*iamentity.Group](func(target *iamentity.Group) (scoped.Resource, bool) {
			return resourceFromEntity(GroupResourceKind, target)
		}),
		scoped.TypedResourceResolver[*iamentity.Role](func(target *iamentity.Role) (scoped.Resource, bool) {
			return resourceFromEntity(RoleResourceKind, target)
		}),
		scoped.TypedResourceResolver[*iamentity.Tenant](func(target *iamentity.Tenant) (scoped.Resource, bool) {
			return platformResourceFromEntity(TenantResourceKind, target)
		}),
		scoped.TypedResourceResolver[*iamentity.MenuItem](func(target *iamentity.MenuItem) (scoped.Resource, bool) {
			return platformResourceFromEntity(MenuResourceKind, target)
		}),
		scoped.TypedResourceResolver[*iamentity.Scope](func(target *iamentity.Scope) (scoped.Resource, bool) {
			return platformResourceFromEntity(ScopeResourceKind, target)
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
