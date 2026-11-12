package router

import (
	"reflect"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	"gochen-runtime/api/rest"
	runtimehttp "gochen-runtime/http"
	"gochen/app/query"
	"gochen/errors"
	"gochen/httpx"
)

// TenantRoutes 租户路由注册器
type TenantRoutes struct {
	tenantService   ITenantService
	tenantRepo      *tenantrepo.TenantRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      *svc.IAMAccess
	userRepo        *userrepo.UserRepo
	groupRepo       *grouprepo.GroupRepo
	roleRepo        *rolerepo.RoleRepo
	scopeRepo       *scoperepo.ScopeRepo
	standard        *tenantHTTPApplication
}

// NewTenantRoutes 创建租户路由注册器
func NewTenantRoutes(
	tenantService ITenantService,
	tenantRepo *tenantrepo.TenantRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAccess,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	roleRepo *rolerepo.RoleRepo,
	scopeRepo *scoperepo.ScopeRepo,
) (*TenantRoutes, error) {
	tr := &TenantRoutes{
		tenantService:   tenantService,
		tenantRepo:      tenantRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
		userRepo:        userRepo,
		groupRepo:       groupRepo,
		roleRepo:        roleRepo,
		scopeRepo:       scopeRepo,
	}
	if err := validateTenantRouteService(tenantService); err != nil {
		return nil, err
	}
	application, err := newTenantCRUDApplication(tr)
	if err != nil {
		return nil, err
	}
	tr.standard = &tenantHTTPApplication{application: application}
	return tr, nil
}

// RegisterRoutes 注册路由
func (tr *TenantRoutes) RegisterRoutes(group httpx.IRouteGroup) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}
	if tr == nil || tr.standard == nil {
		return errors.NewCode(errors.InvalidInput, "tenant routes require the declared tenant service")
	}
	if err := validateTenantRouteService(tr.tenantService); err != nil {
		return err
	}
	tenantGroup := group.Group("/tenants")

	// tenant 资源是 platform-scoped：HTTP 入口先收口 active scope，
	// permission + write guard 再由 builder / service 统一处理。
	adminGroup := tenantGroup.Group("")
	adminGroup.Use(iammw.PlatformScopeMiddleware())

	if err := rest.Mount(adminGroup, tr.standard,
		rest.WithPagination[*tenantHTTPModel, int64](10, 100),
		rest.WithResponseWrapper[*tenantHTTPModel, int64](tr.wrapTenantResponse),
	); err != nil {
		if appErr, ok := err.(*errors.AppError); ok && appErr != nil {
			return appErr.Wrap("build tenant crud routes").WithContext("route", "iam.tenant")
		}
		return errors.Wrap(err, errors.Internal, "failed to build tenant crud routes").WithContext("route", "iam.tenant")
	}

	return tr.setupTenantCustomRoutes(adminGroup)
}

func validateTenantRouteService(service ITenantService) error {
	if service == nil || reflect.ValueOf(service).Kind() == reflect.Pointer && reflect.ValueOf(service).IsNil() {
		return errors.NewCode(errors.InvalidInput, "tenant routes require the declared tenant service")
	}
	for _, action := range []string{"http_activate", "http_deactivate", "http_repair"} {
		if _, err := service.AuthorizationBinding(action); err != nil {
			return err
		}
	}
	return nil
}

// Name 获取注册器名称
func (tr *TenantRoutes) Name() string {
	return "tenant"
}

// Priority 获取注册优先级
func (tr *TenantRoutes) Priority() int {
	return 50 // 租户路由优先级，在 auth/user 之后
}

// setupTenantCustomRoutes 设置租户自定义路由
func (tr *TenantRoutes) setupTenantCustomRoutes(group httpx.IRouteGroup) error {
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		path, action string
		handler      httpx.Handler
	}{
		{"/:id/activate", "http_activate", tr.activateTenant},
		{"/:id/deactivate", "http_deactivate", tr.deactivateTenant},
		{"/:id/repair-root-scope", "http_repair", tr.repairTenantRootScope},
	} {
		binding, err := tr.tenantService.AuthorizationBinding(entry.action)
		if err != nil {
			return err
		}
		if registry != nil {
			if err := runtimehttp.BindEntry(group, "POST", entry.path, binding); err != nil {
				return err
			}
		}
		if err := runtimehttp.RegisterRoute(group, "POST", entry.path, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (tr *TenantRoutes) wrapTenantResponse(data any) any {
	switch payload := data.(type) {
	case *tenantHTTPModel:
		return payload.view
	case []*tenantHTTPModel:
		items := make([]svc.TenantListItem, 0, len(payload))
		for _, tenant := range payload {
			if tenant == nil {
				continue
			}
			items = append(items, tenant.view)
		}
		return map[string]any{
			"items": items,
			"total": len(items),
		}
	case query.PagedResult[*tenantHTTPModel]:
		items := make([]svc.TenantListItem, 0, len(payload.Data))
		for _, tenant := range payload.Data {
			if tenant == nil {
				continue
			}
			items = append(items, tenant.view)
		}
		return map[string]any{
			"items":       items,
			"total":       payload.Total,
			"page":        payload.Page,
			"size":        payload.Size,
			"total_pages": payload.TotalPages,
			"has_next":    payload.HasNext,
			"has_prev":    payload.HasPrev,
		}
	default:
		return data
	}
}

func tenantListItem(tenant *iamentity.Tenant) svc.TenantListItem {
	item := svc.TenantListItem{
		ID:          tenant.ID,
		Key:         tenant.Key,
		Name:        tenant.Name,
		Description: tenant.Description,
		Status:      tenant.Status,
		RootScopeID: tenant.RootScopeID,
		CreatedAt:   tenant.CreatedAt,
		UpdatedAt:   tenant.UpdatedAt,
		DeletedAt:   tenant.DeletedAt,
	}
	return item
}

// activateTenant 启用租户
func (tr *TenantRoutes) activateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if _, err := tr.tenantService.ExecuteHTTP(reqCtx, "activate", tenantsvc.TenantCommandInput{ID: id}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusActive,
	})
}

// deactivateTenant 禁用租户
func (tr *TenantRoutes) deactivateTenant(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	if _, err := tr.tenantService.ExecuteHTTP(reqCtx, "deactivate", tenantsvc.TenantCommandInput{ID: id}); err != nil {
		return err
	}

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":     id,
		"status": svc.TenantStatusInactive,
	})
}

// repairTenantRootScope 修复租户 root scope。
func (tr *TenantRoutes) repairTenantRootScope(ctx httpx.IContext) error {
	reqCtx := ctx.RequestContext()
	id, err := httpx.ParseInt64Param(ctx, "id")
	if err != nil {
		return err
	}

	result, err := tr.tenantService.ExecuteHTTP(reqCtx, "repair", tenantsvc.TenantCommandInput{ID: id})
	if err != nil {
		return err
	}
	scope := result.Scope

	return httpx.WriteSuccess(ctx, map[string]any{
		"id":             id,
		"root_scope_id":  scope.ID,
		"root_scope_key": scope.Key,
		"root_scope_status": func() string {
			if scope.IsActive() {
				return iamentity.ScopeStatusActive
			}
			return iamentity.ScopeStatusInactive
		}(),
	})
}
