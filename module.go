package iam

import (
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	menurepo "gochen-iam/repo/menu"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamrouter "gochen-iam/router"
	iamservice "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	menusvc "gochen-iam/service/menu"
	rolesvc "gochen-iam/service/role"
	scopesvc "gochen-iam/service/scope"
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen-iam/tenant"
	"gochen/boot"
	"gochen/errors"
	"gochen/host/module"
	"gochen/httpx"
)

// NewModule 创建 IAM 领域模块
func NewModule() (module.IModule, error) {
	tenant.InstallTenantResolver()
	if err := iamservice.InstallIAMPermissionCatalog(); err != nil {
		return nil, err
	}
	return boot.BuildModule(
		boot.Module("iam").
			Name("IAM").
			PermissionDefinitions(iamservice.IAMAuthzPermissionDefinitions()...).
			ResourceResolver(iamservice.IAMResourceResolvers()...).
			Provide(
				// Repos
				tenantrepo.NewTenantRepository,
				userrepo.NewUserRepository,
				grouprepo.NewGroupRepository,
				rolerepo.NewRoleRepository,
				scoperepo.NewScopeRepository,
				menurepo.NewMenuItemRepository,
				// Services
				iamservice.NewScopeAuthorizer,
				iamservice.NewAuthContextResolver,
				iamservice.InstallAuthContextResolver,
				iamservice.NewIAMAuthorizer,
				tenantsvc.NewTenantService,
				scopesvc.NewScopeService,
				usersvc.NewUserService,
				groupsvc.NewGroupService,
				rolesvc.NewRoleService,
				menusvc.NewMenuService,
			).
			RouteRegistrar(
				iamrouter.NewAuthRoutes,
				iamrouter.NewUserRoutes,
				iamrouter.NewRoleRoutes,
				iamrouter.NewGroupRoutes,
				iamrouter.NewTenantRoutes,
				iamrouter.NewScopeRoutes,
				iamrouter.NewMenuRoutes,
				NewAuthConfigValidator,
			).
			// IAM 模块既包含匿名可访问的登录/注册端点，也包含需要鉴权的管理端点。
			// 使用 OptionalAuthMiddleware 统一解析 token（若存在），供后续 PermissionMiddleware 等使用。
			Middleware(
				iammw.OptionalAuthMiddleware(nil),
			),
	), nil
}

// authConfigValidator 在启动期对鉴权配置做 fail-fast 校验。
//
// 说明：
// - ValidateAuthConfig 负责校验 JWT 密钥与生产环境安全约束（如禁止 query token）；
// - 将其放到模块启动链路里，避免仅靠运行期“带 token 的请求”才暴露配置错误。
type authConfigValidator struct{}

// NewAuthConfigValidator 创建鉴权配置Validator。
//
// 通过显式依赖 AuthContextResolver，确保 access token 运行时 resolver 在模块启动期完成安装。
func NewAuthConfigValidator(_ *iamservice.AuthContextResolver) *authConfigValidator {
	return &authConfigValidator{}
}

// RegisterRoutes 注册路由集合。
func (v *authConfigValidator) RegisterRoutes(httpx.IRouteGroup) error {
	if err := iammw.ValidateAuthConfig(nil); err != nil {
		return errors.Wrap(err, errors.Internal, "auth config validation failed")
	}
	return nil
}
