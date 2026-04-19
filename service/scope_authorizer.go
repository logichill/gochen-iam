package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	"gochen/errors"
)

const (
	platformScopeCode                 = "platform"
	tenantRootScopeStatusHealthy      = "healthy"
	tenantRootScopeStatusMissing      = "missing"
	tenantRootScopeStatusInconsistent = "inconsistent"
)

// ScopeAuthorizer 统一封装 active scope 解析、tenant->scope 映射与覆盖判定。
//
// 第一阶段仍保留当前 tenant 业务模型，但所有“能否跨 tenant 操作”的判断
// 都应收敛到这里，而不是散落在 service/router 中硬编码 role 名称。
type ScopeAuthorizer struct {
	scopeRepo  *scoperepo.ScopeRepo
	tenantRepo *tenantrepo.TenantRepo
}

func NewScopeAuthorizer(scopeRepo *scoperepo.ScopeRepo, tenantRepo *tenantrepo.TenantRepo) *ScopeAuthorizer {
	return &ScopeAuthorizer{
		scopeRepo:  scopeRepo,
		tenantRepo: tenantRepo,
	}
}

func (a *ScopeAuthorizer) EnsurePlatformScope(ctx context.Context) (*iamentity.Scope, error) {
	scope, err := a.scopeRepo.FindByKey(ctx, platformScopeCode)
	if err == nil {
		return scope, nil
	}
	if !errors.Is(err, errors.NotFound) {
		return nil, err
	}

	scope = &iamentity.Scope{
		Key:    platformScopeCode,
		Name:   "Platform",
		Type:   iamentity.ScopeTypePlatform,
		Path:   iamentity.ScopePathFor("", platformScopeCode),
		Depth:  0,
		Status: iamentity.ScopeStatusActive,
	}
	scope.SetUpdatedAt(time.Now())
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	guard, err := NewPlatformCreateConstraint(ctx, ScopeResourceKind)
	if err != nil {
		return nil, err
	}
	if err := a.scopeRepo.CreateWithConstraint(ctx, scope, guard); err != nil {
		// 并发 create 时回读即可。
		if reloaded, reloadErr := a.scopeRepo.FindByKey(ctx, platformScopeCode); reloadErr == nil {
			return reloaded, nil
		}
		return nil, errors.Wrap(err, errors.Database, "创建 platform scope 失败")
	}
	if err := a.scopeRepo.RebuildVisibilityMap(ctx); err != nil {
		return nil, err
	}
	return scope, nil
}

func (a *ScopeAuthorizer) EnsureTenantRootScope(ctx context.Context, tenant *iamentity.Tenant) (*iamentity.Scope, error) {
	if tenant == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
	}
	platformScope, err := a.EnsurePlatformScope(ctx)
	if err != nil {
		return nil, err
	}

	scopeKey := fmt.Sprintf("tenant:%s", strings.TrimSpace(tenant.Key))
	if tenant.RootScopeID != nil && *tenant.RootScopeID > 0 {
		currentScope, err := a.scopeRepo.Get(ctx, *tenant.RootScopeID)
		if err == nil && currentScope != nil && currentScope.Key == scopeKey {
			return a.ensureTenantRootScopeState(ctx, tenant, platformScope, currentScope)
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}

	scope, err := a.scopeRepo.FindByKey(ctx, scopeKey)
	if err == nil {
		return a.ensureTenantRootScopeState(ctx, tenant, platformScope, scope)
	}
	if !errors.Is(err, errors.NotFound) {
		return nil, err
	}

	scope = &iamentity.Scope{
		Key:         scopeKey,
		Name:        tenant.Name,
		Type:        iamentity.ScopeTypeTenant,
		ParentID:    &platformScope.ID,
		Path:        iamentity.ScopePathFor(platformScope.Path, scopeKey),
		Depth:       platformScope.Depth + 1,
		Description: tenant.Description,
		Status:      iamentity.ScopeStatusActive,
	}
	scope.SetUpdatedAt(time.Now())
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	guard, err := NewPlatformCreateConstraint(ctx, ScopeResourceKind)
	if err != nil {
		return nil, err
	}
	if err := a.scopeRepo.CreateWithConstraint(ctx, scope, guard); err != nil {
		if reloaded, reloadErr := a.scopeRepo.FindByKey(ctx, scopeKey); reloadErr == nil {
			scope = reloaded
		} else {
			return nil, errors.Wrap(err, errors.Database, "创建 tenant scope 失败")
		}
	}
	if err := a.scopeRepo.RebuildVisibilityMap(ctx); err != nil {
		return nil, err
	}

	tenant.RootScopeID = &scope.ID
	if tenant.GetID() > 0 {
		guard, err := NewPlatformEntityConstraint(ctx, TenantResourceKind, tenant)
		if err != nil {
			return nil, err
		}
		if err := a.tenantRepo.UpdateWithConstraint(ctx, tenant, guard); err != nil {
			return nil, err
		}
	}
	return scope, nil
}

func (a *ScopeAuthorizer) ensureTenantRootScopeState(
	ctx context.Context,
	tenant *iamentity.Tenant,
	platformScope *iamentity.Scope,
	scope *iamentity.Scope,
) (*iamentity.Scope, error) {
	if tenant == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
	}
	if platformScope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "platform scope is required")
	}
	if scope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope is required")
	}

	desiredKey := fmt.Sprintf("tenant:%s", strings.TrimSpace(tenant.Key))
	desiredPath := iamentity.ScopePathFor(platformScope.Path, desiredKey)
	parentChanged := scope.ParentID == nil || *scope.ParentID != platformScope.ID
	needsRepair := scope.Key != desiredKey ||
		scope.Type != iamentity.ScopeTypeTenant ||
		parentChanged ||
		scope.Path != desiredPath ||
		scope.Depth != platformScope.Depth+1 ||
		scope.Status != iamentity.ScopeStatusActive ||
		scope.Name != tenant.Name ||
		scope.Description != tenant.Description

	if needsRepair {
		scope.Key = desiredKey
		scope.Name = tenant.Name
		scope.Type = iamentity.ScopeTypeTenant
		scope.ParentID = &platformScope.ID
		scope.Path = desiredPath
		scope.Depth = platformScope.Depth + 1
		scope.Description = tenant.Description
		scope.Status = iamentity.ScopeStatusActive
		scope.SetUpdatedAt(time.Now())

		guard, err := NewPlatformEntityConstraint(ctx, ScopeResourceKind, scope)
		if err != nil {
			return nil, err
		}
		if err := a.scopeRepo.UpdateWithConstraint(ctx, scope, guard); err != nil {
			return nil, errors.Wrap(err, errors.Database, "修复 tenant root scope 失败")
		}
		if parentChanged {
			if err := a.scopeRepo.RebuildVisibilityMap(ctx); err != nil {
				return nil, err
			}
		}
	}

	if tenant.RootScopeID == nil || *tenant.RootScopeID != scope.ID {
		tenant.RootScopeID = &scope.ID
		if tenant.GetID() > 0 {
			guard, err := NewPlatformEntityConstraint(ctx, TenantResourceKind, tenant)
			if err != nil {
				return nil, err
			}
			if err := a.tenantRepo.UpdateWithConstraint(ctx, tenant, guard); err != nil {
				return nil, err
			}
		}
	}

	return scope, nil
}

func (a *ScopeAuthorizer) TenantRootScopeHealth(ctx context.Context, tenant *iamentity.Tenant) (*TenantRootScopeHealth, error) {
	if tenant == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
	}

	scopeKey := fmt.Sprintf("tenant:%s", strings.TrimSpace(tenant.Key))
	if tenant.RootScopeID == nil || *tenant.RootScopeID <= 0 {
		return &TenantRootScopeHealth{
			Status:    tenantRootScopeStatusMissing,
			Reason:    "tenant root scope 尚未初始化。",
			CanRepair: true,
		}, nil
	}

	scope, err := a.scopeRepo.Get(ctx, *tenant.RootScopeID)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return &TenantRootScopeHealth{
				Status:    tenantRootScopeStatusMissing,
				Reason:    "tenant root scope 记录已失联，可执行修复。",
				CanRepair: true,
			}, nil
		}
		return nil, err
	}
	if scope == nil {
		return &TenantRootScopeHealth{
			Status:    tenantRootScopeStatusMissing,
			Reason:    "tenant root scope 记录为空，可执行修复。",
			CanRepair: true,
		}, nil
	}
	if scope.Key != scopeKey || scope.Type != iamentity.ScopeTypeTenant {
		return &TenantRootScopeHealth{
			Status:    tenantRootScopeStatusInconsistent,
			Reason:    "tenant root scope 与租户标识不一致，可执行修复。",
			CanRepair: true,
		}, nil
	}
	platformScope, err := a.EnsurePlatformScope(ctx)
	if err != nil {
		return nil, err
	}
	expectedPath := iamentity.ScopePathFor(platformScope.Path, scopeKey)
	if scope.ParentID == nil || *scope.ParentID != platformScope.ID || scope.Path != expectedPath || scope.Depth != platformScope.Depth+1 {
		return &TenantRootScopeHealth{
			Status:    tenantRootScopeStatusInconsistent,
			Reason:    "tenant root scope 结构已漂移，可执行修复。",
			CanRepair: true,
		}, nil
	}
	if scope.Status != iamentity.ScopeStatusActive {
		return &TenantRootScopeHealth{
			Status:    tenantRootScopeStatusInconsistent,
			Reason:    "tenant root scope 当前未启用，可执行修复。",
			CanRepair: true,
		}, nil
	}
	return &TenantRootScopeHealth{
		Status:    tenantRootScopeStatusHealthy,
		CanRepair: false,
	}, nil
}

func (a *ScopeAuthorizer) ResolveTenantScope(ctx context.Context, tenantID string) (*iamentity.Scope, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.NewCode(errors.Validation, "tenant_id is required")
	}
	tenant, err := a.tenantRepo.FindByKey(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return a.lookupTenantRootScope(ctx, tenant)
}

func (a *ScopeAuthorizer) lookupTenantRootScope(ctx context.Context, tenant *iamentity.Tenant) (*iamentity.Scope, error) {
	if tenant == nil {
		return nil, errors.NewCode(errors.InvalidInput, "tenant is required")
	}

	scopeKey := fmt.Sprintf("tenant:%s", strings.TrimSpace(tenant.Key))
	if tenant.RootScopeID == nil || *tenant.RootScopeID <= 0 {
		return nil, errors.NewCode(errors.Internal, "tenant root scope is missing")
	}

	scope, err := a.scopeRepo.Get(ctx, *tenant.RootScopeID)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.Internal, "tenant root scope is missing")
		}
		return nil, err
	}
	if scope == nil {
		return nil, errors.NewCode(errors.Internal, "tenant root scope is missing")
	}
	if scope.Key != scopeKey || scope.Type != iamentity.ScopeTypeTenant {
		return nil, errors.NewCode(errors.Internal, "tenant root scope is inconsistent")
	}
	return scope, nil
}

func (a *ScopeAuthorizer) ResolveActiveScope(ctx context.Context) (*iamentity.Scope, error) {
	if ctx == nil {
		return nil, errors.NewCode(errors.Unauthorized, "用户未认证")
	}
	scopeID := activeScopeIDFromContext(ctx)
	if scopeID <= 0 {
		return nil, errors.NewCode(errors.Unauthorized, "active scope is required")
	}
	return a.scopeRepo.Get(ctx, scopeID)
}

func (a *ScopeAuthorizer) ScopeCovers(ctx context.Context, ancestorScopeID, descendantScopeID int64) (bool, error) {
	return a.scopeRepo.ScopeCovers(ctx, ancestorScopeID, descendantScopeID)
}

func (a *ScopeAuthorizer) VisibleScopeIDs(ctx context.Context, scopeID int64) ([]int64, error) {
	return a.scopeRepo.VisibleScopeIDs(ctx, scopeID)
}

func (a *ScopeAuthorizer) Scope(ctx context.Context, scopeID int64) (*iamentity.Scope, error) {
	return a.scopeRepo.Get(ctx, scopeID)
}

func (a *ScopeAuthorizer) RequirePermissionInScope(ctx context.Context, permission string, targetScopeID int64) error {
	if err := requirePrincipalPermission(ctx, permission); err != nil {
		return err
	}
	activeScope, err := a.ResolveActiveScope(ctx)
	if err != nil {
		return err
	}
	covers, err := a.ScopeCovers(ctx, activeScope.ID, targetScopeID)
	if err != nil {
		return err
	}
	if !covers {
		return errors.NewCode(errors.Forbidden, "当前授权域不覆盖目标资源")
	}
	return nil
}

func (a *ScopeAuthorizer) RequirePermissionInTenant(ctx context.Context, permission, tenantID string) error {
	if err := requirePrincipalPermission(ctx, permission); err != nil {
		return err
	}

	resolution, err := resolveTenantAccess(ctx, tenantID)
	if err != nil {
		return err
	}
	if resolution.SkipScopeCheck {
		return nil
	}

	tenantCtx, err := BindTenantContext(ctx, resolution.TenantID)
	if err != nil {
		return err
	}
	targetScope, err := a.ResolveTenantScope(tenantCtx, resolution.TenantID)
	if err != nil {
		return err
	}
	// 覆盖判定必须继续使用调用方原始 active scope；tenant rebound 只用于
	// 解析目标租户 root scope，不能把平台操作员当前生效的 scope 清空。
	return a.RequirePermissionInScope(ctx, permission, targetScope.ID)
}

func (a *ScopeAuthorizer) RequirePlatformPermission(ctx context.Context, permission string) error {
	platformScope, err := a.EnsurePlatformScope(ctx)
	if err != nil {
		return err
	}
	return a.RequirePermissionInScope(ctx, permission, platformScope.ID)
}
