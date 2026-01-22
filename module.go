package iam

import (
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamrouter "gochen-iam/router"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen/runtime/di"
	"gochen/server"
)

// Module IAM 领域模块（身份访问管理）
type Module struct {
	container di.IContainer
}

// NewModule 创建 IAM 领域模块
func NewModule(container di.IContainer) (server.IModule, error) {
	m := &Module{container: container}
	if err := m.registerProviders(); err != nil {
		return nil, err
	}
	return m, nil
}

// Name 返回领域名称
func (m *Module) Name() string {
	return "IAM"
}

func (m *Module) registerProviders() error {
	// 注册仓储层
	repoCtors := []interface{}{
		tenantrepo.NewTenantRepository,
		userrepo.NewUserRepository,
		grouprepo.NewGroupRepository,
		rolerepo.NewRoleRepository,
	}

	for _, ctor := range repoCtors {
		if err := m.container.RegisterConstructor(ctor); err != nil {
			return err
		}
	}

	// 注册服务层
	svcCtors := []interface{}{
		tenantsvc.NewTenantService,
		usersvc.NewUserService,
		groupsvc.NewGroupService,
		rolesvc.NewRoleService,
	}

	for _, ctor := range svcCtors {
		if err := m.container.RegisterConstructor(ctor); err != nil {
			return err
		}
	}
	// 注册路由构造器（路由注册在 Router 层统一完成）
	routeCtors := []interface{}{
		iamrouter.NewAuthRoutes,
		iamrouter.NewUserRoutes,
		iamrouter.NewRoleRoutes,
		iamrouter.NewGroupRoutes,
		iamrouter.NewTenantRoutes,
	}

	for _, ctor := range routeCtors {
		if err := m.container.RegisterConstructor(ctor); err != nil {
			return err
		}
	}

	return nil
}
