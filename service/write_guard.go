package service

import (
	"context"
	"strings"

	iamauth "gochen-iam/auth"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/domain/spec"
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

// DataScopeSpec 把上下文中的数据范围投影为行级规约：
// Global → 全部可见；Filtered → 授权域集合；DenyAll → 零值规约（不匹配任何行）。
func DataScopeSpec(ctx context.Context) spec.Spec {
	scope, ok := scoped.DataScopeFromContext(ctx)
	if !ok {
		return spec.Spec{}
	}
	switch scope.Kind {
	case scoped.ScopeGlobal:
		return spec.All()
	case scoped.ScopeFiltered:
		return scoped.ScopeIn("scope", scope.ScopeIDs...)
	default:
		return spec.Spec{}
	}
}

// CreateWriteSpec 为创建路径返回写规约；平台资源不受 managed scope 约束。
func CreateWriteSpec(ctx context.Context, kind string) spec.Spec {
	if resourceKindUsesManagedScope(kind) {
		return DataScopeSpec(ctx)
	}
	return spec.All()
}

// EntityWriteSpec 为已存在资源返回写规约；版本条件由仓储自动加入。
func EntityWriteSpec(ctx context.Context, kind string, entity tenantVersionedEntity) spec.Spec {
	if entity == nil || resourceKindUsesManagedScope(kind) {
		return CreateWriteSpec(ctx, kind)
	}
	return spec.All()
}

// PlatformWriteSpec 为平台级资源返回写规约。
func PlatformWriteSpec(ctx context.Context) spec.Spec {
	_ = ctx
	return spec.All()
}

func resourceKindUsesManagedScope(kind string) bool {
	switch strings.TrimSpace(kind) {
	case UserResourceKind, GroupResourceKind, RoleResourceKind:
		return true
	default:
		return false
	}
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
	if scope, ok := scoped.DataScopeFromContext(ctx); ok {
		if len(scope.ScopeIDs) == 1 {
			return scope.ScopeIDs[0]
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
