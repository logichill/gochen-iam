package scope

import (
	"context"
	"fmt"
	"strings"
	"time"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen/errors"
)

const (
	scopeHealthStatusHealthy = "healthy"
	scopeHealthStatusDrifted = "drifted"
)

type ScopeService struct {
	scopeRepo       *scoperepo.ScopeRepo
	tenantRepo      *tenantrepo.TenantRepo
	roleRepo        *rolerepo.RoleRepo
	userRepo        *userrepo.UserRepo
	groupRepo       *grouprepo.GroupRepo
	scopeAuthorizer *svc.ScopeAuthorizer
}

func NewScopeService(
	scopeRepo *scoperepo.ScopeRepo,
	tenantRepo *tenantrepo.TenantRepo,
	roleRepo *rolerepo.RoleRepo,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
	scopeAuthorizer *svc.ScopeAuthorizer,
) *ScopeService {
	return &ScopeService{
		scopeRepo:       scopeRepo,
		tenantRepo:      tenantRepo,
		roleRepo:        roleRepo,
		userRepo:        userRepo,
		groupRepo:       groupRepo,
		scopeAuthorizer: scopeAuthorizer,
	}
}

func (s *ScopeService) CreateScope(ctx context.Context, req *svc.CreateScopeRequest) (*iamentity.Scope, error) {
	if err := s.authorizePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}

	parent, err := s.scopeRepo.Get(ctx, req.ParentID)
	if err != nil {
		return nil, err
	}
	if !parent.IsActive() {
		return nil, errors.NewCode(errors.Validation, "父授权域未启用")
	}

	scopeType := strings.ToLower(strings.TrimSpace(req.Type))
	if scopeType == iamentity.ScopeTypePlatform {
		return nil, errors.NewCode(errors.Validation, "platform root scope 只能由系统初始化")
	}
	if scopeType == iamentity.ScopeTypeTenant {
		return nil, errors.NewCode(errors.Validation, "tenant root scope 请通过租户管理创建")
	}

	key := strings.TrimSpace(req.Key)
	if _, err := s.scopeRepo.FindByKey(ctx, key); err == nil {
		return nil, errors.NewCode(errors.Validation, "scope key 已存在")
	} else if !errors.Is(err, errors.NotFound) {
		return nil, err
	}

	status := normalizeScopeStatus(req.Status)
	scope := &iamentity.Scope{
		Key:         key,
		Name:        strings.TrimSpace(req.Name),
		Type:        scopeType,
		ParentID:    &parent.ID,
		Path:        iamentity.ScopePathFor(parent.Path, key),
		Depth:       parent.Depth + 1,
		Description: strings.TrimSpace(req.Description),
		Status:      status,
	}
	scope.SetUpdatedAt(time.Now())
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	guard, err := svc.NewPlatformCreateConstraint(ctx, svc.ScopeResourceKind)
	if err != nil {
		return nil, err
	}
	if err := s.scopeRepo.CreateWithConstraint(ctx, scope, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "创建授权域失败")
	}
	if err := s.scopeRepo.RebuildVisibilityMap(ctx); err != nil {
		return nil, err
	}
	return scope, nil
}

func (s *ScopeService) UpdateScope(ctx context.Context, scopeID int64, req *svc.UpdateScopeRequest) (*iamentity.Scope, error) {
	if err := s.authorizePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}

	scope, err := s.scopeRepo.Get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if err := s.ensureMutableScope(ctx, scope); err != nil {
		return nil, err
	}

	if name := strings.TrimSpace(req.Name); name != "" {
		scope.Name = name
	}
	if description := strings.TrimSpace(req.Description); description != "" {
		scope.Description = description
	}
	if req.Status != "" {
		scope.Status = normalizeScopeStatus(req.Status)
	}
	scope.SetUpdatedAt(time.Now())

	if err := scope.Validate(); err != nil {
		return nil, err
	}
	guard, err := svc.NewPlatformEntityConstraint(ctx, svc.ScopeResourceKind, scope)
	if err != nil {
		return nil, err
	}
	if err := s.scopeRepo.UpdateWithConstraint(ctx, scope, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "更新授权域失败")
	}
	return scope, nil
}

func (s *ScopeService) ActivateScope(ctx context.Context, scopeID int64) error {
	_, err := s.UpdateScope(ctx, scopeID, &svc.UpdateScopeRequest{Status: iamentity.ScopeStatusActive})
	return err
}

func (s *ScopeService) DeactivateScope(ctx context.Context, scopeID int64) error {
	_, err := s.UpdateScope(ctx, scopeID, &svc.UpdateScopeRequest{Status: iamentity.ScopeStatusInactive})
	return err
}

func (s *ScopeService) DeleteScope(ctx context.Context, scopeID int64) error {
	if err := s.authorizePlatformAdmin(ctx); err != nil {
		return err
	}
	scope, err := s.scopeRepo.Get(ctx, scopeID)
	if err != nil {
		return err
	}
	state, err := s.evaluateScopeGovernanceState(ctx, scope)
	if err != nil {
		return err
	}
	if !state.CanDelete {
		return errors.NewCode(errors.Validation, state.DeleteBlockReason)
	}
	guard, err := svc.NewPlatformEntityConstraint(ctx, svc.ScopeResourceKind, scope)
	if err != nil {
		return err
	}
	if err := s.scopeRepo.DeleteWithConstraint(ctx, scopeID, guard); err != nil {
		return errors.Wrap(err, errors.Database, "删除授权域失败")
	}
	if err := s.scopeRepo.RebuildVisibilityMap(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ScopeService) RepairScope(ctx context.Context, scopeID int64) (*iamentity.Scope, error) {
	if err := s.authorizePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	scope, err := s.scopeRepo.Get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if scope.ParentID == nil || *scope.ParentID <= 0 {
		return nil, errors.NewCode(errors.Validation, "root scope 暂不支持在此直接修复")
	}
	if s.tenantRepo != nil {
		tenant, err := s.tenantRepo.FindByRootScopeID(ctx, scope.ID)
		if err == nil && tenant != nil {
			return nil, errors.NewCode(errors.Validation, "tenant root scope 请通过租户管理维护")
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}
	health, err := s.evaluateScopeHealth(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !health.CanRepair {
		if health.HealthReason != "" {
			return nil, errors.NewCode(errors.Validation, health.HealthReason)
		}
		return scope, nil
	}
	parent, err := s.scopeRepo.Get(ctx, *scope.ParentID)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.Validation, "父授权域不存在，无法自动修复")
		}
		return nil, err
	}

	scope.Path = iamentity.ScopePathFor(parent.Path, scope.Key)
	scope.Depth = parent.Depth + 1
	if !parent.IsActive() {
		scope.Status = iamentity.ScopeStatusInactive
	}
	scope.SetUpdatedAt(time.Now())

	if err := scope.Validate(); err != nil {
		return nil, err
	}
	guard, err := svc.NewPlatformEntityConstraint(ctx, svc.ScopeResourceKind, scope)
	if err != nil {
		return nil, err
	}
	if err := s.scopeRepo.UpdateWithConstraint(ctx, scope, guard); err != nil {
		return nil, errors.Wrap(err, errors.Database, "修复授权域结构失败")
	}
	return scope, nil
}

func (s *ScopeService) ScopeGovernanceState(ctx context.Context, scopeID int64) (*svc.ScopeGovernanceState, error) {
	scope, err := s.scopeRepo.Get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	return s.evaluateScopeGovernanceState(ctx, scope)
}

func (s *ScopeService) authorizePlatformAdmin(ctx context.Context) error {
	if s.scopeAuthorizer == nil {
		return errors.NewCode(errors.InvalidInput, "scope authorizer is required")
	}
	return s.scopeAuthorizer.RequirePlatformPermission(ctx, svc.AdminEntryPermission.Code)
}

func (s *ScopeService) ensureMutableScope(ctx context.Context, scope *iamentity.Scope) error {
	if scope == nil {
		return errors.NewCode(errors.InvalidInput, "scope is required")
	}
	if scope.ParentID == nil && strings.EqualFold(scope.Type, iamentity.ScopeTypePlatform) {
		return errors.NewCode(errors.Validation, "platform root scope 不允许在治理台直接修改")
	}
	if s.tenantRepo != nil {
		tenant, err := s.tenantRepo.FindByRootScopeID(ctx, scope.ID)
		if err == nil && tenant != nil {
			return errors.NewCode(errors.Validation, "tenant root scope 请通过租户管理维护")
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return err
		}
	}
	return nil
}

func (s *ScopeService) evaluateScopeGovernanceState(ctx context.Context, scope *iamentity.Scope) (*svc.ScopeGovernanceState, error) {
	if scope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope is required")
	}

	state := &svc.ScopeGovernanceState{
		CanDelete: false,
	}
	health, err := s.evaluateScopeHealth(ctx, scope)
	if err != nil {
		return nil, err
	}
	state.HealthStatus = health.HealthStatus
	state.HealthReason = health.HealthReason
	state.CanRepair = health.CanRepair
	if scope.ParentID == nil {
		state.DeleteBlockReason = "仅 custom child scope 支持删除，root scope 不可删除。"
		return state, nil
	}

	scopeType := strings.ToLower(strings.TrimSpace(scope.Type))
	if scopeType == iamentity.ScopeTypePlatform || scopeType == iamentity.ScopeTypeTenant {
		state.DeleteBlockReason = fmt.Sprintf("%s scope 属于保留类型，不能删除。", scopeType)
		return state, nil
	}

	childCount, err := s.scopeRepo.CountChildren(ctx, scope.ID)
	if err != nil {
		return nil, err
	}
	state.ChildCount = childCount
	if childCount > 0 {
		state.DeleteBlockReason = fmt.Sprintf("当前授权域下仍有 %d 个子授权域，不能删除。", childCount)
		return state, nil
	}

	if s.tenantRepo != nil {
		count, err := s.tenantRepo.CountByRootScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = "当前授权域仍作为租户 root scope，被租户治理引用，不能删除。"
			return state, nil
		}
	}

	if s.roleRepo != nil {
		count, err := s.roleRepo.CountByNamespaceScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个角色用作 namespace scope，不能删除。", count)
			return state, nil
		}
	}

	if s.userRepo != nil {
		count, err := s.userRepo.CountRoleBindingsByGrantScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 条用户角色绑定用作 grant scope，不能删除。", count)
			return state, nil
		}

		count, err = s.userRepo.CountByHomeScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个用户用作 home scope，不能删除。", count)
			return state, nil
		}

		count, err = s.userRepo.CountByManagedScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个用户用作 managed scope，不能删除。", count)
			return state, nil
		}
	}

	if s.groupRepo != nil {
		count, err := s.groupRepo.CountByManagedScopeID(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个组织用作 managed scope，不能删除。", count)
			return state, nil
		}
	}

	state.CanDelete = true
	return state, nil
}

func (s *ScopeService) evaluateScopeHealth(ctx context.Context, scope *iamentity.Scope) (*svc.ScopeGovernanceState, error) {
	state := &svc.ScopeGovernanceState{
		HealthStatus: scopeHealthStatusHealthy,
	}
	if scope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope is required")
	}
	if scope.ParentID == nil || *scope.ParentID <= 0 {
		return state, nil
	}
	if s.tenantRepo != nil {
		tenant, err := s.tenantRepo.FindByRootScopeID(ctx, scope.ID)
		if err == nil && tenant != nil {
			return state, nil
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}

	parent, err := s.scopeRepo.Get(ctx, *scope.ParentID)
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			state.HealthStatus = scopeHealthStatusDrifted
			state.HealthReason = "父授权域不存在，当前结构无法自动修复。"
			return state, nil
		}
		return nil, err
	}

	expectedPath := iamentity.ScopePathFor(parent.Path, scope.Key)
	expectedDepth := parent.Depth + 1
	if scope.Path != expectedPath || scope.Depth != expectedDepth {
		state.HealthStatus = scopeHealthStatusDrifted
		state.HealthReason = "当前授权域的 path/depth 与父授权域不一致，可执行修复。"
		state.CanRepair = true
		return state, nil
	}
	if !parent.IsActive() && scope.IsActive() {
		state.HealthStatus = scopeHealthStatusDrifted
		state.HealthReason = "父授权域已停用，但当前授权域仍处于启用状态，可执行修复。"
		state.CanRepair = true
		return state, nil
	}
	return state, nil
}

func normalizeScopeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case iamentity.ScopeStatusInactive:
		return iamentity.ScopeStatusInactive
	default:
		return iamentity.ScopeStatusActive
	}
}
