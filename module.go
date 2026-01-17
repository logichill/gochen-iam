package iam

import (
	"context"

	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamrouter "gochen-iam/router"
	groupsvc "gochen-iam/service/group"
	rolesvc "gochen-iam/service/role"
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen/eventing/bus"
	"gochen/eventing/projection"
	"gochen/runtime/di"
)

// Module IAM 领域模块（身份访问管理）
type Module struct{}

// NewModule 创建 IAM 领域模块
func NewModule() *Module {
	return &Module{}
}

// Name 返回领域名称
func (m *Module) Name() string {
	return "IAM"
}

// RegisterProviders 注册 IAM 领域的所有提供者
func (m *Module) RegisterProviders(container di.IContainer) error {
	// 注册仓储层
	repoCtors := []interface{}{
		tenantrepo.NewTenantRepository,
		userrepo.NewUserRepository,
		grouprepo.NewGroupRepository,
		rolerepo.NewRoleRepository,
	}

	for _, ctor := range repoCtors {
		if err := container.RegisterConstructor(ctor); err != nil {
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
		if err := container.RegisterConstructor(ctor); err != nil {
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
		if err := container.RegisterConstructor(ctor); err != nil {
			return err
		}
	}

	return nil
}

// RegisterEventHandlers IAM 领域暂无事件处理器
func (m *Module) RegisterEventHandlers(ctx context.Context, eventBus bus.IEventBus, container di.IContainer) error {
	// IAM 领域暂无事件处理器
	return nil
}

// RegisterProjections IAM 领域暂无投影
func (m *Module) RegisterProjections(container di.IContainer) (*projection.ProjectionManager, []string, error) {
	// IAM 领域暂无投影
	return nil, nil, nil
}

// Providers Facade 式调用入口
func (m *Module) Providers(container di.IContainer) error {
	return m.RegisterProviders(container)
}

// EventHandlers Facade 式调用入口
func (m *Module) EventHandlers(ctx context.Context, eventBus bus.IEventBus, container di.IContainer) error {
	return m.RegisterEventHandlers(ctx, eventBus, container)
}

// Projections Facade 式调用入口
func (m *Module) Projections(container di.IContainer) (*projection.ProjectionManager, []string, error) {
	return m.RegisterProjections(container)
}
