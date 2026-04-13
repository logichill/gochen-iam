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
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen-iam/tenant"
	"gochen/boot"
	"gochen/errorx"
	"gochen/httpx"
	"gochen/server"
)

// NewModule 创建 IAM 领域模块
func NewModule() (server.IModule, error) {
	tenant.InstallTenantResolver()
	return boot.BuildModule(boot.ModuleConfig{
		ID:   "iam",
		Name: "IAM",
		Providers: []any{
			// Repos
			tenantrepo.NewTenantRepository,
			userrepo.NewUserRepository,
			grouprepo.NewGroupRepository,
			rolerepo.NewRoleRepository,
			scoperepo.NewScopeRepository,
			menurepo.NewMenuItemRepository,
			// Services
			iamservice.NewScopeAuthorizer,
			iamservice.NewIAMAuthorizer,
			tenantsvc.NewTenantService,
			usersvc.NewUserService,
			groupsvc.NewGroupService,
			rolesvc.NewRoleService,
			menusvc.NewMenuService,
		},
		RouteRegistrars: []any{
			iamrouter.NewAuthRoutes,
			iamrouter.NewUserRoutes,
			iamrouter.NewRoleRoutes,
			iamrouter.NewGroupRoutes,
			iamrouter.NewTenantRoutes,
			iamrouter.NewMenuRoutes,
			NewStrictPermissionRegistryValidator,
			NewAuthConfigValidator,
		},
		// IAM 模块既包含匿名可访问的登录/注册端点，也包含需要鉴权的管理端点。
		// 使用 OptionalAuthMiddleware 统一解析 token（若存在），供后续 PermissionMiddleware 等使用。
		Middlewares: []httpx.Middleware{
			iammw.OptionalAuthMiddleware(nil),
		},
	}), nil
}

type strictPermissionRegistryValidator struct{}

// NewStrictPermissionRegistryValidator 创建Strict权限注册表Validator。
func NewStrictPermissionRegistryValidator() *strictPermissionRegistryValidator {
	return &strictPermissionRegistryValidator{}
}

// RegisterRoutes 注册路由集合。
func (v *strictPermissionRegistryValidator) RegisterRoutes(httpx.IRouteGroup) error {
	// 启动期 fail-close：严格权限字典模式校验（走 error 通道）。
	iammw.RegisterRequiredPermissionDefinitions(iamservice.AllPermissionDefinitions...)
	if err := iammw.ValidateStrictPermissionRegistry(); err != nil {
		return errorx.Wrap(err, errorx.Internal, "strict permission registry validation failed")
	}
	return nil
}

// authConfigValidator 在启动期对鉴权配置做 fail-fast 校验。
//
// 说明：
// - ValidateAuthConfig 负责校验 JWT 密钥与生产环境安全约束（如禁止 query token）；
// - 将其放到模块启动链路里，避免仅靠运行期“带 token 的请求”才暴露配置错误。
type authConfigValidator struct{}

// NewAuthConfigValidator 创建鉴权配置Validator。
func NewAuthConfigValidator() *authConfigValidator { return &authConfigValidator{} }

// RegisterRoutes 注册路由集合。
func (v *authConfigValidator) RegisterRoutes(httpx.IRouteGroup) error {
	if err := iammw.ValidateAuthConfig(nil); err != nil {
		return errorx.Wrap(err, errorx.Internal, "auth config validation failed")
	}
	return nil
}
