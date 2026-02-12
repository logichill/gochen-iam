package iam

import (
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	menurepo "gochen-iam/repo/menu"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamrouter "gochen-iam/router"
	iamservice "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	menusvc "gochen-iam/service/menu"
	rolesvc "gochen-iam/service/role"
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen/errorx"
	"gochen/httpx"
	"gochen/server"
)

// NewModule 创建 IAM 领域模块
func NewModule() (server.IModule, error) {
	return server.BuildModule(server.ModuleConfig{
		ID:   "iam",
		Name: "IAM",
		Constructors: []any{
			// Repos
			tenantrepo.NewTenantRepository,
			userrepo.NewUserRepository,
			grouprepo.NewGroupRepository,
			rolerepo.NewRoleRepository,
			menurepo.NewMenuItemRepository,
			// Services
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
		},
		// IAM 模块既包含匿名可访问的登录/注册端点，也包含需要鉴权的管理端点。
		// 使用 OptionalAuthMiddleware 统一解析 token（若存在），供后续 PermissionMiddleware 等使用。
		Middlewares: []httpx.Middleware{
			iammw.OptionalAuthMiddleware(nil),
		},
	}), nil
}

type strictPermissionRegistryValidator struct{}

func NewStrictPermissionRegistryValidator() *strictPermissionRegistryValidator {
	return &strictPermissionRegistryValidator{}
}

func (v *strictPermissionRegistryValidator) RegisterRoutes(httpx.IRouteGroup) error {
	// 启动期 fail-close：严格权限字典模式校验（走 error 通道）。
	iammw.RegisterRequiredPermissions(iamservice.AllPermissions...)
	if err := iammw.ValidateStrictPermissionRegistry(); err != nil {
		return errorx.Wrap(err, errorx.Internal, "strict permission registry validation failed")
	}
	return nil
}
