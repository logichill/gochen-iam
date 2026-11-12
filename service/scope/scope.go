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
	scopeRepo  *scoperepo.ScopeRepo
	tenantRepo *tenantrepo.TenantRepo
	roleRepo   *rolerepo.RoleRepo
	userRepo   *userrepo.UserRepo
	groupRepo  *grouprepo.GroupRepo
	commands   map[string]*scopeCommand
	catalogs   map[string]*scopeCatalog
}

func NewScopeService(
	scopeRepo *scoperepo.ScopeRepo,
	tenantRepo *tenantrepo.TenantRepo,
	roleRepo *rolerepo.RoleRepo,
	userRepo *userrepo.UserRepo,
	groupRepo *grouprepo.GroupRepo,
) (*ScopeService, error) {
	s := &ScopeService{
		scopeRepo:  scopeRepo,
		tenantRepo: tenantRepo,
		roleRepo:   roleRepo,
		userRepo:   userRepo,
		groupRepo:  groupRepo,
	}
	if err := s.compileCommands(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ScopeService) createScope(ctx context.Context, req *svc.CreateScopeRequest, access *scopeAccess) (*iamentity.Scope, error) {
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}

	parent, err := access.get(ctx, req.ParentID)
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
	if _, err := access.findKey(ctx, key); err == nil {
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

	scope, err = access.save(ctx, "create", scope)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "创建授权域失败")
	}
	if err := access.rebuild(ctx); err != nil {
		return nil, err
	}
	return scope, nil
}

func (s *ScopeService) updateScope(ctx context.Context, scopeID int64, req *svc.UpdateScopeRequest, access *scopeAccess) (*iamentity.Scope, error) {
	if req == nil {
		return nil, errors.NewCode(errors.Validation, "请求不能为空")
	}

	scope, err := access.get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if err := s.ensureMutableScope(ctx, scope, access); err != nil {
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
	scope, err = access.save(ctx, "update", scope)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "更新授权域失败")
	}
	return scope, nil
}

func (s *ScopeService) deleteScope(ctx context.Context, scopeID int64, access *scopeAccess) error {
	scope, err := access.get(ctx, scopeID)
	if err != nil {
		return err
	}
	state, err := s.evaluateScopeGovernanceState(ctx, scope, access)
	if err != nil {
		return err
	}
	if !state.CanDelete {
		return errors.NewCode(errors.Validation, state.DeleteBlockReason)
	}
	if _, err := access.save(ctx, "delete", scope); err != nil {
		return errors.Wrap(err, errors.Database, "删除授权域失败")
	}
	if err := access.rebuild(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ScopeService) repairScope(ctx context.Context, scopeID int64, access *scopeAccess) (*iamentity.Scope, error) {
	scope, err := access.get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	if scope.ParentID == nil || *scope.ParentID <= 0 {
		return nil, errors.NewCode(errors.Validation, "root scope 暂不支持在此直接修复")
	}
	if access.tenants != nil {
		tenant, err := access.findTenant(ctx, scope.ID)
		if err == nil && tenant != nil {
			return nil, errors.NewCode(errors.Validation, "tenant root scope 请通过租户管理维护")
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}
	health, err := s.evaluateScopeHealth(ctx, scope, access)
	if err != nil {
		return nil, err
	}
	if !health.CanRepair {
		if health.HealthReason != "" {
			return nil, errors.NewCode(errors.Validation, health.HealthReason)
		}
		return scope, nil
	}
	parent, err := access.get(ctx, *scope.ParentID)
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
	scope, err = access.save(ctx, "update", scope)
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "修复授权域结构失败")
	}
	return scope, nil
}

func (s *ScopeService) governanceState(ctx context.Context, scopeID int64, access *scopeAccess) (*svc.ScopeGovernanceState, error) {
	scope, err := access.get(ctx, scopeID)
	if err != nil {
		return nil, err
	}
	return s.evaluateScopeGovernanceState(ctx, scope, access)
}

func (s *ScopeService) ensureMutableScope(ctx context.Context, scope *iamentity.Scope, access *scopeAccess) error {
	if scope == nil {
		return errors.NewCode(errors.InvalidInput, "scope is required")
	}
	if scope.ParentID == nil && strings.EqualFold(scope.Type, iamentity.ScopeTypePlatform) {
		return errors.NewCode(errors.Validation, "platform root scope 不允许在治理台直接修改")
	}
	if access.tenants != nil {
		tenant, err := access.findTenant(ctx, scope.ID)
		if err == nil && tenant != nil {
			return errors.NewCode(errors.Validation, "tenant root scope 请通过租户管理维护")
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return err
		}
	}
	return nil
}

func (s *ScopeService) evaluateScopeGovernanceState(ctx context.Context, scope *iamentity.Scope, access *scopeAccess) (*svc.ScopeGovernanceState, error) {
	if scope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope is required")
	}

	state := &svc.ScopeGovernanceState{
		CanDelete: false,
	}
	health, err := s.evaluateScopeHealth(ctx, scope, access)
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

	childCount, err := access.children(ctx, scope.ID)
	if err != nil {
		return nil, err
	}
	state.ChildCount = childCount
	if childCount > 0 {
		state.DeleteBlockReason = fmt.Sprintf("当前授权域下仍有 %d 个子授权域，不能删除。", childCount)
		return state, nil
	}

	if access.tenants != nil {
		count, err := access.countTenant(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = "当前授权域仍作为租户 root scope，被租户治理引用，不能删除。"
			return state, nil
		}
	}

	if access.roles != nil {
		count, err := access.roles.Read(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个角色用作 namespace scope，不能删除。", count)
			return state, nil
		}
	}

	if access.users != nil {
		count, err := access.bindings.Read(ctx, scope.ID)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 条用户角色绑定用作 grant scope，不能删除。", count)
			return state, nil
		}

		count, err = access.users.Read(ctx, userReferenceInput{ID: scope.ID, Home: true})
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个用户用作 home scope，不能删除。", count)
			return state, nil
		}

		count, err = access.users.Read(ctx, userReferenceInput{ID: scope.ID})
		if err != nil {
			return nil, err
		}
		if count > 0 {
			state.DeleteBlockReason = fmt.Sprintf("当前授权域仍被 %d 个用户用作 managed scope，不能删除。", count)
			return state, nil
		}
	}

	if access.groups != nil {
		count, err := access.groups.Read(ctx, scope.ID)
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

func (s *ScopeService) evaluateScopeHealth(ctx context.Context, scope *iamentity.Scope, access *scopeAccess) (*svc.ScopeGovernanceState, error) {
	state := &svc.ScopeGovernanceState{
		HealthStatus: scopeHealthStatusHealthy,
	}
	if scope == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope is required")
	}
	if scope.ParentID == nil || *scope.ParentID <= 0 {
		return state, nil
	}
	if access.tenants != nil {
		tenant, err := access.findTenant(ctx, scope.ID)
		if err == nil && tenant != nil {
			return state, nil
		}
		if err != nil && !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}

	parent, err := access.get(ctx, *scope.ParentID)
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
