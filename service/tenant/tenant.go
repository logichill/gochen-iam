package tenant

import (
	"context"
	"time"

	iamentity "gochen-iam/entity"
	iamperm "gochen-iam/permissions"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen/db/orm"
	"gochen/domain/spec"
	"gochen/errors"
)

// TenantService 租户服务（普通 CRUD / 可审计模型）
type TenantService struct {
	tenantRepo      *tenantrepo.TenantRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	authorizer      *svc.IAMAuthorizer
}

// NewTenantService 创建租户服务实例
func NewTenantService(
	tenantRepo *tenantrepo.TenantRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
	authorizer *svc.IAMAuthorizer,
) *TenantService {
	return &TenantService{
		tenantRepo:      tenantRepo,
		scopeAuthorizer: scopeAuthorizer,
		authorizer:      authorizer,
	}
}

// CreateTenant 创建租户（默认状态为 inactive，由上层应用显式启用）
func (s *TenantService) CreateTenant(ctx context.Context, req *svc.CreateTenantRequest) (*iamentity.Tenant, error) {
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionWrite), &iamentity.Tenant{}); err != nil {
		return nil, err
	}
	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, err
	}

	// 校验编码唯一
	if _, err := s.tenantRepo.FindByKey(ctx, req.Key); err == nil {
		return nil, errors.NewCode(errors.Validation, "租户编码已存在")
	} else if !errors.Is(err, errors.NotFound) {
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

	guard, err := svc.AuthorizeWriteSpec(ctx, s.authorizer, svc.TenantPermissionSet.Code(iamperm.ActionWrite), tenant)
	if err != nil {
		return nil, err
	}
	if s.scopeAuthorizer == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope authorizer is required")
	}
	if err := s.tenantRepo.WithinTx(ctx, func(txCtx context.Context) error {
		if err := s.tenantRepo.Create(txCtx, tenant, guard); err != nil {
			return errors.Wrap(err, errors.Database, "保存租户失败")
		}
		_, err := s.scopeAuthorizer.EnsureTenantRootScope(txCtx, tenant)
		return err
	}); err != nil {
		return nil, err
	}

	return tenant, nil
}

// UpdateTenant 更新租户信息
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID int64, req *svc.UpdateTenantRequest) (*iamentity.Tenant, error) {
	tenant, err := s.tenantRepo.Get(ctx, tenantID, spec.All())
	if err != nil {
		return nil, err
	}
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionWrite), tenant); err != nil {
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

	guard, err := svc.AuthorizeWriteSpec(ctx, s.authorizer, svc.TenantPermissionSet.Code(iamperm.ActionWrite), tenant)
	if err != nil {
		return nil, err
	}
	if err := s.tenantRepo.Update(ctx, tenant, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "更新租户失败")
	}

	return tenant, nil
}

// ActivateTenant 启用租户
func (s *TenantService) ActivateTenant(ctx context.Context, tenantID int64) error {
	tenant, err := s.tenantRepo.Get(ctx, tenantID, spec.All())
	if err != nil {
		return err
	}
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionActivate), tenant); err != nil {
		return err
	}

	tenant.Activate()
	guard, err := svc.AuthorizeWriteSpec(ctx, s.authorizer, svc.TenantPermissionSet.Code(iamperm.ActionActivate), tenant)
	if err != nil {
		return err
	}
	if err := s.tenantRepo.Update(ctx, tenant, guard); err != nil {
		return errors.Wrap(err, errors.Database, "启用租户失败")
	}
	return nil
}

// DeactivateTenant 禁用租户
func (s *TenantService) DeactivateTenant(ctx context.Context, tenantID int64) error {
	tenant, err := s.tenantRepo.Get(ctx, tenantID, spec.All())
	if err != nil {
		return err
	}
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionActivate), tenant); err != nil {
		return err
	}

	tenant.Deactivate()
	guard, err := svc.AuthorizeWriteSpec(ctx, s.authorizer, svc.TenantPermissionSet.Code(iamperm.ActionActivate), tenant)
	if err != nil {
		return err
	}
	if err := s.tenantRepo.Update(ctx, tenant, guard); err != nil {
		return errors.Wrap(err, errors.Database, "禁用租户失败")
	}
	return nil
}

// RepairTenantRootScope 修复或重建租户 root scope。
func (s *TenantService) RepairTenantRootScope(ctx context.Context, tenantID int64) (*iamentity.Scope, error) {
	tenant, err := s.tenantRepo.Get(ctx, tenantID, spec.All())
	if err != nil {
		return nil, err
	}
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionWrite), tenant); err != nil {
		return nil, err
	}
	if s.scopeAuthorizer == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope authorizer is required")
	}
	return s.scopeAuthorizer.EnsureTenantRootScope(ctx, tenant)
}

// Tenant 获取单个租户
func (s *TenantService) Tenant(ctx context.Context, tenantID int64) (*iamentity.Tenant, error) {
	tenant, err := s.tenantRepo.Get(ctx, tenantID, spec.All())
	if err != nil {
		return nil, err
	}
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionRead), tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

// ListTenants 获取租户列表
func (s *TenantService) ListTenants(ctx context.Context) ([]*iamentity.Tenant, error) {
	if err := s.authorizePlatform(ctx, svc.TenantPermissionSet.Code(iamperm.ActionRead), &iamentity.Tenant{}); err != nil {
		return nil, err
	}
	model, err := s.tenantRepo.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var tenants []*iamentity.Tenant
	err = model.Find(ctx, &tenants, orm.WithWhere("deleted_at IS NULL"))
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询租户列表失败")
	}
	return tenants, nil
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

func (s *TenantService) authorizePlatform(ctx context.Context, permission string, targets ...any) error {
	if s.authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "authorizer is required")
	}
	return svc.RequireAuthorization(ctx, s.authorizer, permission, targets...)
}
