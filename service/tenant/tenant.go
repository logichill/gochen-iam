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
	tenantRepo *tenantrepo.TenantRepo
}

// NewTenantService 创建租户服务实例
func NewTenantService(tenantRepo *tenantrepo.TenantRepo) *TenantService {
	return &TenantService{
		tenantRepo: tenantRepo,
	}
}

// CreateTenant 创建租户（默认状态为 inactive，由上层应用显式启用）
func (s *TenantService) CreateTenant(ctx context.Context, req *svc.CreateTenantRequest) (*iamentity.Tenant, error) {
	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, err
	}

	// 校验编码唯一
	if _, err := s.tenantRepo.FindByKey(ctx, req.Key); err == nil {
		return nil, errors.NewError(errors.ErrCodeValidation, "租户编码已存在")
	} else if !errors.IsNotFound(err) {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "检查租户编码失败")
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

	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "保存租户失败")
	}

	return tenant, nil
}

// UpdateTenant 更新租户信息
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID int64, req *svc.UpdateTenantRequest) (*iamentity.Tenant, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
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

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "更新租户失败")
	}

	return tenant, nil
}

// ActivateTenant 启用租户
func (s *TenantService) ActivateTenant(ctx context.Context, tenantID int64) error {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}

	tenant.Activate()
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "启用租户失败")
	}
	return nil
}

// DeactivateTenant 禁用租户
func (s *TenantService) DeactivateTenant(ctx context.Context, tenantID int64) error {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return err
	}

	tenant.Deactivate()
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return errors.WrapError(err, errors.ErrCodeDatabase, "禁用租户失败")
	}
	return nil
}

// GetTenant 获取单个租户
func (s *TenantService) GetTenant(ctx context.Context, tenantID int64) (*iamentity.Tenant, error) {
	return s.tenantRepo.GetByID(ctx, tenantID)
}

// ListTenants 获取租户列表
func (s *TenantService) ListTenants(ctx context.Context) ([]*iamentity.Tenant, error) {
	var tenants []*iamentity.Tenant
	err := s.tenantRepo.Model().Find(ctx, &tenants)
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrCodeDatabase, "查询租户列表失败")
	}
	return tenants, nil
}

// ----------------- 校验辅助 -----------------

func (s *TenantService) validateCreateTenantRequest(req *svc.CreateTenantRequest) error {
	if req == nil {
		return errors.NewError(errors.ErrCodeValidation, "请求不能为空")
	}
	if req.Key == "" {
		return errors.NewError(errors.ErrCodeValidation, "租户编码不能为空")
	}
	if req.Name == "" {
		return errors.NewError(errors.ErrCodeValidation, "租户名称不能为空")
	}
	return nil
}

