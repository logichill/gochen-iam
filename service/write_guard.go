package service

import (
	"context"
	"strconv"
	"strings"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	"gochen/app/access"
	"gochen/authz"
	"gochen/errorx"
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
		return WriteConstraint{}, errorx.New(errorx.InvalidInput, "entity is required")
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return WriteConstraint{}, errorx.New(errorx.InvalidInput, "resource kind is required")
	}
	resource := authz.Resource{
		Kind:     kind,
		ID:       strconv.FormatInt(entity.GetID(), 10),
		OwnerID:  tenantOwnerID(strings.TrimSpace(entity.GetTenantID())),
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
	return iamaccess.NewWriteConstraint(authz.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
}

// NewPlatformCreateConstraint 为 platform-scoped 资源创建显式写约束。
func NewPlatformCreateConstraint(ctx context.Context, kind string) (WriteConstraint, error) {
	return newPlatformWriteConstraint(kind, "", "")
}

// NewPlatformEntityConstraint 为已存在的 platform-scoped 资源构造带 revision 的显式写约束。
func NewPlatformEntityConstraint(ctx context.Context, kind string, entity writeConstraintVersionedEntity) (WriteConstraint, error) {
	if entity == nil {
		return WriteConstraint{}, errorx.New(errorx.InvalidInput, "entity is required")
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
		return WriteConstraint{}, errorx.New(errorx.InvalidInput, "resource kind is required")
	}
	resource := authz.Resource{
		Kind:     kind,
		ID:       resourceID,
		OwnerID:  tenantOwnerID(tenantID),
		Revision: revision,
	}
	if resourceKindUsesManagedScope(kind) {
		resource.ManagedScopeID = managedScopeIDFromContext(ctx)
	}
	return iamaccess.NewWriteConstraint(authz.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
}

func newPlatformWriteConstraint(kind, resourceID, revision string) (WriteConstraint, error) {
	kind = strings.TrimSpace(kind)
	resourceID = strings.TrimSpace(resourceID)
	revision = strings.TrimSpace(revision)
	if kind == "" {
		return WriteConstraint{}, errorx.New(errorx.InvalidInput, "resource kind is required")
	}
	resource := authz.Resource{
		Kind:     kind,
		ID:       resourceID,
		Revision: revision,
	}
	return iamaccess.NewWriteConstraint(authz.AllowDecision(resource).WriteConstraint(), access.ConstraintMetadata{}), nil
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
	if scope, ok := authz.DataScopeFromContext(ctx); ok {
		if scope.ActiveScopeID > 0 {
			return scope.ActiveScopeID
		}
		if len(scope.VisibleScopeIDs) == 1 {
			return scope.VisibleScopeIDs[0]
		}
	}
	if principal, ok := authz.PrincipalFromContext(ctx); ok {
		if principal.ActiveScopeID > 0 {
			return principal.ActiveScopeID
		}
	}
	return 0
}

func managedScopeIDFromContext(ctx context.Context) int64 {
	return ManagedScopeIDFromContext(ctx)
}
