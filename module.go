package iam

import (
	"context"
	"reflect"
	"sort"

	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	menurepo "gochen-iam/repo/menu"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	iamrouter "gochen-iam/router"
	groupsvc "gochen-iam/service/group"
	menusvc "gochen-iam/service/menu"
	rolesvc "gochen-iam/service/role"
	tenantsvc "gochen-iam/service/tenant"
	usersvc "gochen-iam/service/user"
	"gochen/runtime/di"
	"gochen/runtime/errorx"
	"gochen/server"
)

// Module IAM 领域模块（身份访问管理）
type Module struct {
	container di.IContainer
	opts      server.ModuleInitOptions
}

// NewModule 创建 IAM 领域模块
func NewModule() (server.IModule, error) {
	return &Module{}, nil
}

// Name 返回领域名称
func (m *Module) Name() string {
	return "IAM"
}

func (m *Module) ID() string { return "iam" }

func (m *Module) Init(opts server.ModuleInitOptions) error {
	m.opts = opts
	m.container = opts.Container
	return m.registerProviders()
}

type routeRegistrar = server.RouteRegistrar

// RegisterRoutes 仅挂载 HTTP 路由与执行启动期校验，不进入运行期。
func (m *Module) RegisterRoutes(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if m.opts.HTTP == nil {
		return nil
	}
	group := m.opts.HTTP.MountGroup()
	if group == nil {
		return nil
	}

	registrars, err := m.resolveRouteRegistrars()
	if err != nil {
		return err
	}
	sort.Slice(registrars, func(i, j int) bool {
		pi, pj := registrars[i].GetPriority(), registrars[j].GetPriority()
		if pi == pj {
			return registrars[i].GetName() < registrars[j].GetName()
		}
		return pi < pj
	})

	for _, r := range registrars {
		if r == nil {
			continue
		}
		if err := server.SafeRegisterRoutes(r, group); err != nil {
			return err
		}
	}

	// 启动期 fail-close：严格权限字典模式校验（走 error 通道）。
	if err := iammw.ValidateStrictPermissionRegistry(); err != nil {
		return errorx.WrapError(err, errorx.Internal, "strict permission registry validation failed")
	}
	return nil
}

func (m *Module) Start(ctx context.Context) (server.ModuleStopFunc, error) {
	if m == nil {
		return nil, nil
	}
	if m.opts.HTTP == nil {
		return nil, nil
	}
	return nil, nil
}

func (m *Module) registerProviders() error {
	// 注册仓储层
	repoCtors := []interface{}{
		tenantrepo.NewTenantRepository,
		userrepo.NewUserRepository,
		grouprepo.NewGroupRepository,
		rolerepo.NewRoleRepository,
		menurepo.NewMenuItemRepository,
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
		menusvc.NewMenuService,
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
		iamrouter.NewMenuRoutes,
	}

	for _, ctor := range routeCtors {
		if err := m.container.RegisterConstructor(ctor); err != nil {
			return err
		}
	}

	return nil
}

func (m *Module) resolveRouteRegistrars() ([]routeRegistrar, error) {
	if m == nil || m.container == nil {
		return nil, nil
	}

	types := []reflect.Type{
		server.ElemType((*iamrouter.AuthRoutes)(nil)),
		server.ElemType((*iamrouter.UserRoutes)(nil)),
		server.ElemType((*iamrouter.RoleRoutes)(nil)),
		server.ElemType((*iamrouter.GroupRoutes)(nil)),
		server.ElemType((*iamrouter.TenantRoutes)(nil)),
		server.ElemType((*iamrouter.MenuRoutes)(nil)),
	}

	out := make([]routeRegistrar, 0, len(types))
	for _, t := range types {
		inst, err := server.ResolveByType(m.container, t)
		if err != nil {
			return nil, err
		}
		r, ok := inst.(routeRegistrar)
		if !ok || server.IsTypedNil(r) {
			return nil, errorx.NewInternalError("resolved route registrar has invalid type").
				WithContext("type", t.String()).
				WithContext("value_type", server.TypeString(inst))
		}
		out = append(out, r)
	}
	return out, nil
}
