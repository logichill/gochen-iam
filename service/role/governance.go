package role

import (
	"context"
	"strings"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen/domain/crud"
	"gochen/errors"
)

type roleGovernanceRepo interface {
	svc.IResourceContextRepository[*iamentity.Role, int64]
	FindByName(ctx context.Context, name string) (*iamentity.Role, error)
	CountGroupsByRoleID(ctx context.Context, roleID int64) (int64, error)
}

type roleUsageCounter interface {
	CountByRoleID(ctx context.Context, roleID int64) (int64, error)
}

// Governance 统一收敛角色 CRUD 的业务治理规则。
type Governance struct {
	roleRepo        roleGovernanceRepo
	userRepo        roleUsageCounter
	scopeAuthorizer *svc.ScopeAuthorizer
}

// NewGovernance 创建角色治理器。
func NewGovernance(
	roleRepo roleGovernanceRepo,
	userRepo roleUsageCounter,
	scopeAuthorizer *svc.ScopeAuthorizer,
) *Governance {
	return &Governance{
		roleRepo:        roleRepo,
		userRepo:        userRepo,
		scopeAuthorizer: scopeAuthorizer,
	}
}

// PrepareCreate 在持久化前补齐默认字段并校验创建规则。
func (g *Governance) PrepareCreate(ctx context.Context, role *iamentity.Role) error {
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	if g == nil || g.roleRepo == nil {
		return errors.NewCode(errors.InvalidInput, "role governance is not configured")
	}

	tenantID, err := svc.NormalizeTenantID(ctx, role.TenantID)
	if err != nil {
		return err
	}
	tenantCtx, err := svc.BindTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}

	role.SetTenantID(tenantID)
	role.SetOwnerID(svc.TenantOwnerID(tenantID))
	role.Code = role.Name
	role.IsSystem = false
	role.Status = svc.RoleStatusActive

	namespaceScope, err := g.resolveNamespaceScopeForCreate(tenantCtx, role)
	if err != nil {
		return err
	}
	if namespaceScope != nil {
		role.NamespaceScopeID = namespaceScope.ID
	}

	if err := validateRoleMutation(role, true); err != nil {
		return err
	}
	if err := g.ensureNameUnique(tenantCtx, role.Name, 0); err != nil {
		return err
	}
	if err := validatePermissionsForScope([]string(role.Permissions), namespaceScope); err != nil {
		return err
	}

	role.SetUpdatedAt(time.Now())
	return nil
}

// PrepareUpdate 在持久化前收敛可变字段并校验更新规则。
func (g *Governance) PrepareUpdate(ctx context.Context, role *iamentity.Role) error {
	if g == nil || g.roleRepo == nil {
		return errors.NewCode(errors.InvalidInput, "role governance is not configured")
	}
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}

	current, tenantCtx, err := svc.LoadTenantBoundResource(ctx, g.roleRepo, role.GetID())
	if err != nil {
		return err
	}
	if _, err := svc.RequireTenantMatch(ctx, current.GetTenantID()); err != nil {
		return err
	}
	return g.PrepareUpdateWithCurrent(tenantCtx, current, role)
}

// PrepareUpdateWithCurrent 复用已加载的当前角色执行更新治理。
func (g *Governance) PrepareUpdateWithCurrent(
	ctx context.Context,
	current *iamentity.Role,
	role *iamentity.Role,
) error {
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	if current == nil {
		return errors.NewCode(errors.InvalidInput, "current role is required")
	}
	if g == nil || g.roleRepo == nil {
		return errors.NewCode(errors.InvalidInput, "role governance is not configured")
	}
	if _, err := svc.RequireTenantMatch(ctx, current.GetTenantID()); err != nil {
		return err
	}

	if current.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色不能被修改")
	}

	role.SetTenantID(current.GetTenantID())
	role.SetOwnerID(current.GetOwnerID())
	role.NamespaceScopeID = current.NamespaceScopeID
	role.Code = current.Code
	role.IsSystem = current.IsSystem
	role.Status = current.Status

	if err := validateRoleMutation(role, true); err != nil {
		return err
	}

	namespaceScope, err := g.resolveNamespaceScopeForRole(ctx, role)
	if err != nil {
		return err
	}
	if err := g.ensureNameUnique(ctx, role.Name, current.GetID()); err != nil {
		return err
	}
	if err := validatePermissionsForScope([]string(role.Permissions), namespaceScope); err != nil {
		return err
	}

	role.SetUpdatedAt(time.Now())
	return nil
}

// ValidateDelete 校验删除前治理规则。
func (g *Governance) ValidateDelete(ctx context.Context, roleID int64) error {
	if g == nil || g.roleRepo == nil {
		return errors.NewCode(errors.InvalidInput, "role governance is not configured")
	}

	role, tenantCtx, err := svc.LoadTenantBoundResource(ctx, g.roleRepo, roleID)
	if err != nil {
		return err
	}
	if _, err := svc.RequireTenantMatch(ctx, role.GetTenantID()); err != nil {
		return err
	}
	return g.ValidateDeleteWithRole(tenantCtx, role)
}

// ValidateDeleteWithRole 复用已加载的当前角色执行删除治理。
func (g *Governance) ValidateDeleteWithRole(ctx context.Context, role *iamentity.Role) error {
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	if g == nil || g.roleRepo == nil || g.userRepo == nil {
		return errors.NewCode(errors.InvalidInput, "role governance is not configured")
	}
	if _, err := svc.RequireTenantMatch(ctx, role.GetTenantID()); err != nil {
		return err
	}

	if role.IsSystem {
		return errors.NewCode(errors.Validation, "系统角色不能被删除")
	}

	userCount, err := g.userRepo.CountByRoleID(ctx, role.GetID())
	if err != nil {
		return err
	}
	if userCount > 0 {
		return errors.NewCode(errors.Validation, "角色正在被用户使用，不能删除")
	}

	groupCount, err := g.roleRepo.CountGroupsByRoleID(ctx, role.GetID())
	if err != nil {
		return err
	}
	if groupCount > 0 {
		return errors.NewCode(errors.Validation, "角色正在被组织使用，不能删除")
	}

	return nil
}

func (g *Governance) ensureNameUnique(ctx context.Context, name string, selfID int64) error {
	existingRole, err := g.roleRepo.FindByName(ctx, name)
	if err != nil && !errors.Is(err, errors.NotFound) {
		return errors.Wrap(err, errors.Database, "检查角色名称失败")
	}
	if existingRole != nil && existingRole.GetID() != selfID {
		return errors.NewCode(errors.Validation, "角色名称已存在")
	}
	return nil
}

func (g *Governance) resolveNamespaceScopeForCreate(
	ctx context.Context,
	role *iamentity.Role,
) (*iamentity.Scope, error) {
	if g.scopeAuthorizer != nil {
		scope, err := g.scopeAuthorizer.ResolveTenantScope(ctx, role.GetTenantID())
		if err != nil {
			return nil, err
		}
		return scope, nil
	}

	if role.NamespaceScopeID <= 0 {
		role.NamespaceScopeID = svc.ManagedScopeIDFromContext(ctx)
	}
	if role.NamespaceScopeID <= 0 {
		return nil, errors.NewCode(errors.InvalidInput, "namespace scope boundary is required")
	}
	scopeKind := strings.TrimSpace(iamauth.ActiveScopeKindFromContext(ctx))
	if scopeKind == "" {
		return nil, nil
	}
	return &iamentity.Scope{Entity: crud.Entity[int64]{ID: role.NamespaceScopeID}, Type: scopeKind}, nil
}

func (g *Governance) resolveNamespaceScopeForRole(
	ctx context.Context,
	role *iamentity.Role,
) (*iamentity.Scope, error) {
	if role == nil {
		return nil, errors.NewCode(errors.InvalidInput, "role is required")
	}
	if g.scopeAuthorizer == nil {
		scopeKind := strings.TrimSpace(iamauth.ActiveScopeKindFromContext(ctx))
		if scopeKind == "" {
			return nil, nil
		}
		return &iamentity.Scope{Entity: crud.Entity[int64]{ID: role.NamespaceScopeID}, Type: scopeKind}, nil
	}
	if role.NamespaceScopeID > 0 {
		scope, err := g.scopeAuthorizer.Scope(ctx, role.NamespaceScopeID)
		if err == nil {
			return scope, nil
		}
		if !errors.Is(err, errors.NotFound) {
			return nil, err
		}
	}
	return g.scopeAuthorizer.ResolveTenantScope(ctx, role.GetTenantID())
}

func validateRoleMutation(role *iamentity.Role, requirePermissions bool) error {
	if role == nil {
		return errors.NewCode(errors.InvalidInput, "role is required")
	}
	if err := role.Validate(); err != nil {
		return err
	}
	if requirePermissions && len(role.Permissions) == 0 {
		return errors.NewCode(errors.Validation, "角色必须至少拥有一个权限")
	}
	return nil
}

func validatePermissions(permissions []string) error {
	for _, permission := range permissions {
		if !iammw.IsValidPermissionCode(permission) {
			return errors.NewCode(errors.Validation, "无效的权限: "+permission)
		}
	}

	if err := iammw.EnsureStrictPermissionRegistryLoaded(); err != nil {
		return err
	}
	for _, permission := range permissions {
		if !iammw.HasRequiredPermission(permission) {
			return errors.NewCode(errors.Validation, "未知权限: "+permission)
		}
	}
	return nil
}

func validatePermissionsForScope(permissions []string, namespaceScope *iamentity.Scope) error {
	if err := validatePermissions(permissions); err != nil {
		return err
	}
	if namespaceScope == nil {
		return nil
	}

	namespaceType := strings.TrimSpace(namespaceScope.Type)
	for _, permission := range permissions {
		definition := iammw.PermissionCode(permission).Definition()
		for _, current := range iammw.RequiredPermissionDefinitions() {
			if strings.EqualFold(current.Code, definition.Code) {
				definition = current
				break
			}
		}
		if definition.BuiltinOnly {
			return errors.NewCode(errors.Validation, "内置通配权限不能授予自定义角色: "+permission)
		}
		if len(definition.Scopes) == 0 {
			continue
		}
		allowed := false
		for _, scopeType := range definition.Scopes {
			if strings.EqualFold(scopeType, namespaceType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.NewCode(errors.Validation, "权限不允许在当前作用域定义: "+permission)
		}
	}
	return nil
}
