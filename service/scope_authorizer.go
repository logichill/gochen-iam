package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	"gochen/errorx"
)

const (
	platformScopeCode = "platform"
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
	if !errorx.Is(err, errorx.NotFound) {
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
	guard, err := NewPlatformCreateWriteGuard(ctx, ScopeResourceKind)
	if err != nil {
		return nil, err
	}
	if err := a.scopeRepo.CreateWithWriteGuard(ctx, scope, guard); err != nil {
		// 并发 create 时回读即可。
		if reloaded, reloadErr := a.scopeRepo.FindByKey(ctx, platformScopeCode); reloadErr == nil {
			return reloaded, nil
		}
		return nil, errorx.Wrap(err, errorx.Database, "创建 platform scope 失败")
	}
	return scope, nil
}

func (a *ScopeAuthorizer) EnsureTenantRootScope(ctx context.Context, tenant *iamentity.Tenant) (*iamentity.Scope, error) {
	if tenant == nil {
		return nil, errorx.New(errorx.InvalidInput, "tenant is required")
	}
	platformScope, err := a.EnsurePlatformScope(ctx)
	if err != nil {
		return nil, err
	}
	if tenant.IsPlatform {
		tenant.RootScopeID = &platformScope.ID
		if tenant.GetID() > 0 {
			guard, err := NewPlatformEntityWriteGuard(ctx, TenantResourceKind, tenant)
			if err != nil {
				return nil, err
			}
			if err := a.tenantRepo.UpdateWithWriteGuard(ctx, tenant, guard); err != nil {
				return nil, err
			}
		}
		return platformScope, nil
	}

	scopeKey := fmt.Sprintf("tenant:%s", strings.TrimSpace(tenant.Key))
	if tenant.RootScopeID != nil && *tenant.RootScopeID > 0 {
		currentScope, err := a.scopeRepo.Get(ctx, *tenant.RootScopeID)
		if err == nil && currentScope != nil && currentScope.Key == scopeKey {
			return currentScope, nil
		}
		if err != nil && !errorx.Is(err, errorx.NotFound) {
			return nil, err
		}
	}

	scope, err := a.scopeRepo.FindByKey(ctx, scopeKey)
	if err == nil {
		tenant.RootScopeID = &scope.ID
		if tenant.GetID() > 0 {
			guard, guardErr := NewPlatformEntityWriteGuard(ctx, TenantResourceKind, tenant)
			if guardErr != nil {
				return nil, guardErr
			}
			if updateErr := a.tenantRepo.UpdateWithWriteGuard(ctx, tenant, guard); updateErr != nil {
				return nil, updateErr
			}
		}
		return scope, nil
	}
	if !errorx.Is(err, errorx.NotFound) {
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
	guard, err := NewPlatformCreateWriteGuard(ctx, ScopeResourceKind)
	if err != nil {
		return nil, err
	}
	if err := a.scopeRepo.CreateWithWriteGuard(ctx, scope, guard); err != nil {
		if reloaded, reloadErr := a.scopeRepo.FindByKey(ctx, scopeKey); reloadErr == nil {
			scope = reloaded
		} else {
			return nil, errorx.Wrap(err, errorx.Database, "创建 tenant scope 失败")
		}
	}

	tenant.RootScopeID = &scope.ID
	if tenant.GetID() > 0 {
		guard, err := NewPlatformEntityWriteGuard(ctx, TenantResourceKind, tenant)
		if err != nil {
			return nil, err
		}
		if err := a.tenantRepo.UpdateWithWriteGuard(ctx, tenant, guard); err != nil {
			return nil, err
		}
	}
	return scope, nil
}

func (a *ScopeAuthorizer) ResolveTenantScope(ctx context.Context, tenantID string) (*iamentity.Scope, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errorx.New(errorx.Validation, "tenant_id is required")
	}
	tenant, err := a.tenantRepo.FindByKey(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return a.EnsureTenantRootScope(ctx, tenant)
}

func (a *ScopeAuthorizer) ResolveActiveScope(ctx context.Context) (*iamentity.Scope, error) {
	if ctx == nil {
		return nil, errorx.New(errorx.Unauthorized, "用户未认证")
	}

	if scopeID := activeScopeIDFromContext(ctx); scopeID > 0 {
		return a.scopeRepo.Get(ctx, scopeID)
	}

	activeTenantID, err := TenantIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return a.ResolveTenantScope(ctx, activeTenantID)
}

func (a *ScopeAuthorizer) ScopeCovers(ctx context.Context, ancestorScopeID, descendantScopeID int64) (bool, error) {
	return a.scopeRepo.ScopeCovers(ctx, ancestorScopeID, descendantScopeID)
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
		return errorx.New(errorx.Forbidden, "当前授权域不覆盖目标资源")
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
	return a.RequirePermissionInScope(tenantCtx, permission, targetScope.ID)
}

func (a *ScopeAuthorizer) RequirePlatformPermission(ctx context.Context, permission string) error {
	platformScope, err := a.EnsurePlatformScope(ctx)
	if err != nil {
		return err
	}
	return a.RequirePermissionInScope(ctx, permission, platformScope.ID)
}
