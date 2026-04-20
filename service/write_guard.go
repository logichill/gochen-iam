package service

import (
	"context"
	"strconv"
	"strings"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	"gochen/auth"
	"gochen/auth/access"
	"gochen/errors"
)

const tenantOwnerPrefix = "tenant:"

type tenantVersionedEntity interface {
	GetID() int64
	GetVersion() uint64
	GetTenantID() string
}

type managedScopeEntity interface {
	GetManagedScopeID() int64
}

type ownerEntity interface {
	GetOwnerID() string
}

type writeConstraintVersionedEntity interface {
	GetID() int64
	GetVersion() uint64
}

// NewCreateWriteConstraint 为单资源创建写入构造显式写约束。
func NewCreateWriteConstraint(ctx context.Context, kind, tenantID string) (WriteConstraint, error) {
	return newWriteConstraint(ctx, kind, strings.TrimSpace(tenantID), "", "")
}

// NewEntityWriteConstraint 为已存在资源构造带 revision 的显式写约束。
func NewEntityWriteConstraint(ctx context.Context, kind string, entity tenantVersionedEntity) (WriteConstraint, error) {
	if entity == nil {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "entity is required")
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "resource kind is required")
	}
	tenantID := strings.TrimSpace(entity.GetTenantID())
	resource := auth.Resource{
		Kind:     kind,
		ID:       strconv.FormatInt(entity.GetID(), 10),
		TenantID: tenantID,
		OwnerID:  tenantOwnerID(tenantID),
		Revision: strconv.FormatUint(entity.GetVersion(), 10),
	}
	if ownable, ok := any(entity).(ownerEntity); ok && strings.TrimSpace(ownable.GetOwnerID()) != "" {
		resource.OwnerID = strings.TrimSpace(ownable.GetOwnerID())
	}
	if scoped, ok := any(entity).(managedScopeEntity); ok && scoped.GetManagedScopeID() > 0 {
		resource.ManagedScopeID = scoped.GetManagedScopeID()
	} else if resourceKindUsesManagedScope(kind) {
		resource.ManagedScopeID = managedScopeIDFromContext(ctx)
	}
	return iamaccess.NewWriteConstraint(auth.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
}

// NewPlatformCreateConstraint 为 platform-scoped 资源创建显式写约束。
//
// 调用约定：调用方需在上游已完成 authz 授权判定（如 router 层的
// PermissionMiddleware + platform scope kind 检查，或 bootstrap 阶段
// 显式的 IsSystem principal 场景）。本函数仅负责把已批准的写入范围
// 投影为仓储可消费的 WriteConstraint，不做授权决策。
func NewPlatformCreateConstraint(ctx context.Context, kind string) (WriteConstraint, error) {
	return newPlatformWriteConstraint(kind, "", "")
}

// NewPlatformEntityConstraint 为已存在的 platform-scoped 资源构造带 revision 的显式写约束。
//
// 语义与 NewPlatformCreateConstraint 相同：假定授权判定已在上游完成，
// 本函数仅为平台级资源的 update/delete 构造带 revision 的写边界。
func NewPlatformEntityConstraint(ctx context.Context, kind string, entity writeConstraintVersionedEntity) (WriteConstraint, error) {
	if entity == nil {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "entity is required")
	}
	_ = ctx
	return newPlatformWriteConstraint(
		kind,
		strconv.FormatInt(entity.GetID(), 10),
		strconv.FormatUint(entity.GetVersion(), 10),
	)
}

func newWriteConstraint(ctx context.Context, kind, tenantID, resourceID, revision string) (WriteConstraint, error) {
	kind = strings.TrimSpace(kind)
	tenantID = strings.TrimSpace(tenantID)
	resourceID = strings.TrimSpace(resourceID)
	revision = strings.TrimSpace(revision)
	if kind == "" {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "resource kind is required")
	}
	resource := auth.Resource{
		Kind:     kind,
		ID:       resourceID,
		TenantID: tenantID,
		OwnerID:  tenantOwnerID(tenantID),
		Revision: revision,
	}
	if resourceKindUsesManagedScope(kind) {
		resource.ManagedScopeID = managedScopeIDFromContext(ctx)
	}
	return iamaccess.NewWriteConstraint(auth.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
}

func newPlatformWriteConstraint(kind, resourceID, revision string) (WriteConstraint, error) {
	kind = strings.TrimSpace(kind)
	resourceID = strings.TrimSpace(resourceID)
	revision = strings.TrimSpace(revision)
	if kind == "" {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "resource kind is required")
	}
	resource := auth.Resource{
		Kind:        kind,
		ID:          resourceID,
		GlobalScope: true,
		Revision:    revision,
	}
	return iamaccess.NewWriteConstraint(auth.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
}

func tenantOwnerID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ""
	}
	return tenantOwnerPrefix + tenantID
}

func TenantOwnerID(tenantID string) string {
	return tenantOwnerID(tenantID)
}

func ManagedScopeIDFromContext(ctx context.Context) int64 {
	if scopeID := iamauth.ActiveScopeIDFromContext(ctx); scopeID > 0 {
		return scopeID
	}
	if scope, ok := auth.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		if principal.ActiveScopeID > 0 {
			return principal.ActiveScopeID
		}
	}
	return 0
}

func managedScopeIDFromContext(ctx context.Context) int64 {
	return ManagedScopeIDFromContext(ctx)
}
