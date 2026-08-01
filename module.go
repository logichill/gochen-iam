package iam

import (
	"context"
	"strings"

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
	iamtenant "gochen-iam/tenant"
	auth "gochen/auth"
	"gochen/db"
	"gochen/errors"
	"gochen/host"
	"gochen/host/module"
	"gochen/host/module/runtimecap"
	"gochen/httpx"
)

// NewModule 使用应用主数据库装配 IAM 领域模块。
func NewModule(database db.IDatabase) (module.IModule, error) {
	store, err := iammw.NewDatabaseRevokedTokenStore(database)
	if err != nil {
		return nil, err
	}
	if err := iammw.InstallDefaultRevokedTokenStore(store); err != nil {
		return nil, err
	}
	authConfig := iammw.DefaultAuthConfig()
	authConfig.RevokedTokenStore = store
	authRoutesProvider := func(userService iamrouter.IUserService) *iamrouter.AuthRoutes {
		return iamrouter.NewAuthRoutesWithConfig(userService, authConfig)
	}
	authConfigValidatorProvider := func(resolver *iamservice.AuthContextResolver) *authConfigValidator {
		return newAuthConfigValidator(resolver, authConfig)
	}
	base, err := host.Module("iam").
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
			newAuthContextResolver,
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
			authRoutesProvider,
			iamrouter.NewUserRoutes,
			iamrouter.NewRoleRoutes,
			iamrouter.NewGroupRoutes,
			iamrouter.NewTenantRoutes,
			iamrouter.NewScopeRoutes,
			iamrouter.NewMenuRoutes,
			authConfigValidatorProvider,
		).
		// IAM 模块既包含匿名可访问的登录/注册端点，也包含需要鉴权的管理端点。
		// 使用 OptionalAuthMiddleware 统一解析 token（若存在），供后续 PermissionMiddleware 等使用。
		Middleware(
			iamModuleAuthMiddleware(authConfig),
		).
		Build()
	if err != nil {
		return nil, err
	}
	return &iamModule{IModule: base}, nil
}

func iamModuleAuthMiddleware(authConfig *iammw.AuthConfig) httpx.Middleware {
	authMiddleware := iammw.OptionalAuthMiddleware(authConfig)
	return func(ctx httpx.IContext, next func() error) error {
		if ctx != nil && isIAMAnonymousAuthPath(ctx.Path()) {
			return next()
		}
		return authMiddleware(ctx, next)
	}
}

func isIAMAnonymousAuthPath(path string) bool {
	path = strings.TrimSuffix(strings.TrimSpace(path), "/")
	for _, suffix := range []string{
		"/auth/login",
		"/auth/csrf",
		"/auth/register",
		"/auth/activate-scope",
		"/auth/forgot-password",
		"/auth/reset-password",
		"/auth/logout",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// newAuthContextResolver binds the resolver to IAM's single authoritative user
// service. Keeping the concrete dependency here avoids ambiguous automatic
// interface adaptation during module registration.
func newAuthContextResolver(scopeAuthorizer *iamservice.ScopeAuthorizer, userService *usersvc.UserService) *iamservice.AuthContextResolver {
	return iamservice.NewAuthContextResolver(scopeAuthorizer, userService)
}

type iamModule struct {
	module.IModule
}

func (m *iamModule) Init(opts module.ModuleInitOptions) error {
	if err := iamservice.InstallIAMPermissionCatalog(runtimecap.AuthzRegistryFrom(opts)); err != nil {
		return err
	}
	return m.IModule.Init(opts)
}

func (m *iamModule) RegisterRoutes(ctx context.Context) error {
	if routeModule, ok := m.IModule.(interface {
		RegisterRoutes(context.Context) error
	}); ok {
		return routeModule.RegisterRoutes(ctx)
	}
	return nil
}

func (m *iamModule) AuthzRegistration() auth.ModuleRegistration {
	if provider, ok := m.IModule.(interface {
		AuthzRegistration() auth.ModuleRegistration
	}); ok {
		return provider.AuthzRegistration()
	}
	return auth.ModuleRegistration{}
}

// PublicFeatures 声明前端可在登录前读取的 IAM 部署模式。
func (m *iamModule) PublicFeatures() []module.PublicFeature {
	return []module.PublicFeature{{Key: "tenant_mode", Value: string(iamtenant.Current().Mode)}}
}

// authConfigValidator 在启动期对鉴权配置做 fail-fast 校验。
//
// 说明：
// - ValidateAuthConfig 负责校验 JWT 密钥与生产环境安全约束（如禁止 query token）；
// - 将其放到模块启动链路里，避免仅靠运行期“带 token 的请求”才暴露配置错误。
type authConfigValidator struct {
	config *iammw.AuthConfig
}

// NewAuthConfigValidator 创建鉴权配置Validator。
//
// 通过显式依赖 AuthContextResolver，确保 access token 运行时 resolver 在模块启动期完成安装。
func NewAuthConfigValidator(_ *iamservice.AuthContextResolver) *authConfigValidator {
	return &authConfigValidator{config: iammw.DefaultAuthConfig()}
}

func newAuthConfigValidator(_ *iamservice.AuthContextResolver, config *iammw.AuthConfig) *authConfigValidator {
	return &authConfigValidator{config: config}
}

// RegisterRoutes 注册路由集合。
func (v *authConfigValidator) RegisterRoutes(httpx.IRouteGroup) error {
	if err := iammw.ValidateAuthConfig(v.config); err != nil {
		return errors.Wrap(err, errors.Internal, "auth config validation failed")
	}
	return nil
}
