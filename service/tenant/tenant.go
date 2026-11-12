package tenant

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen/errors"
)

// TenantService 租户服务（普通 CRUD / 可审计模型）
type TenantService struct {
	tenantRepo      *tenantrepo.TenantRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      *svc.IAMAccess
	commands        map[string]*tenantCommand
	rootProvider    *tenantRootCatalog
}

// NewTenantService 创建租户服务实例
func NewTenantService(
	tenantRepo *tenantrepo.TenantRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAccess,
) (*TenantService, error) {
	s := &TenantService{
		tenantRepo:      tenantRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
	}
	if err := s.compileCommands(); err != nil {
		return nil, err
	}
	return s, nil
}

// CreateTenant 创建租户（默认状态为 inactive，由上层应用显式启用）
func (s *TenantService) CreateTenant(ctx context.Context, req *svc.CreateTenantRequest) (*iamentity.Tenant, error) {
	out, err := s.execute(ctx, "create", TenantCommandInput{Create: req})
	return out.Tenant, err
}

func (s *TenantService) createTenant(ctx context.Context, req *svc.CreateTenantRequest, access *tenantAccess) (*iamentity.Tenant, error) {
	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, err
	}

	// 校验编码唯一
	if exists, err := access.names.Read(ctx, req.Key); err == nil && exists {
		return nil, errors.NewCode(errors.Validation, "租户编码已存在")
	} else if err != nil {
		return nil, errors.Wrap(err, errors.Database, "检查租户编码失败")
	}
	tenant := &iamentity.Tenant{
		Key:         req.Key,
		Name:        req.Name,
		Description: req.Description,
		Status:      svc.TenantStatusInactive,
	}
	tenant.SetUpdatedAt(time.Now())

	if err := tenant.Validate(); err != nil {
		return nil, err
	}

	var result *iamentity.Tenant
	if err := s.tenantRepo.WithinTx(ctx, func(txCtx context.Context) error {
		if err := access.tenant.Create(txCtx, tenant); err != nil {
			return errors.Wrap(err, errors.Database, "保存租户失败")
		}
		if err := access.remember(tenant); err != nil {
			return err
		}
		root, err := access.root.Write(txCtx, tenant)
		if err == nil {
			tenant.RootScopeID = &root.ID
			result, err = access.tenant.Get(txCtx, tenant.ID)
		}
		return err
	}); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateTenant 更新租户信息
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID int64, req *svc.UpdateTenantRequest) (*iamentity.Tenant, error) {
	out, err := s.execute(ctx, "update", TenantCommandInput{ID: tenantID, Update: req})
	return out.Tenant, err
}

func (s *TenantService) updateTenant(ctx context.Context, tenantID int64, req *svc.UpdateTenantRequest, access *tenantAccess) (*iamentity.Tenant, error) {
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}
	tenant, err := access.tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Description != "" {
		tenant.Description = req.Description
	}
	tenant.SetUpdatedAt(time.Now())

	if err := tenant.Validate(); err != nil {
		return nil, err
	}

	if err := access.tenant.Update(ctx, tenant); err != nil {
		return nil, errors.Wrap(err, errors.Database, "更新租户失败")
	}

	return tenant, nil
}

// ActivateTenant 启用租户
func (s *TenantService) ActivateTenant(ctx context.Context, tenantID int64) error {
	_, err := s.execute(ctx, "activate", TenantCommandInput{ID: tenantID})
	return err
}

// DeactivateTenant 禁用租户
func (s *TenantService) DeactivateTenant(ctx context.Context, tenantID int64) error {
	_, err := s.execute(ctx, "deactivate", TenantCommandInput{ID: tenantID})
	return err
}

// RepairTenantRootScope 修复或重建租户 root scope。
func (s *TenantService) RepairTenantRootScope(ctx context.Context, tenantID int64) (*iamentity.Scope, error) {
	out, err := s.execute(ctx, "repair", TenantCommandInput{ID: tenantID})
	return out.Scope, err
}

// Tenant 获取单个租户
func (s *TenantService) Tenant(ctx context.Context, tenantID int64) (*iamentity.Tenant, error) {
	out, err := s.execute(ctx, "read", TenantCommandInput{ID: tenantID})
	return out.Tenant, err
}

// ListTenants 获取租户列表
func (s *TenantService) ListTenants(ctx context.Context) ([]*iamentity.Tenant, error) {
	out, err := s.execute(ctx, "list", TenantCommandInput{})
	return out.Tenants, err
}

// ----------------- 校验辅助 -----------------

// validateCreateTenantRequest 校验创建租户请求。
func (s *TenantService) validateCreateTenantRequest(req *svc.CreateTenantRequest) error {
	if req == nil {
		return errors.NewCode(errors.Validation, "请求不能为空")
	}
	if req.Key == "" {
		return errors.NewCode(errors.Validation, "租户编码不能为空")
	}
	if req.Name == "" {
		return errors.NewCode(errors.Validation, "租户名称不能为空")
	}
	return nil
}
