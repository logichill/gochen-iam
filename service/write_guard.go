package service

import (
	"context"
	"strconv"
	"strings"

	iammw "gochen-iam/middleware"
	"gochen/authz"
	"gochen/errorx"
)

type tenantVersionedEntity interface {
	GetID() int64
	GetVersion() uint64
	GetTenantID() string
}

type writeGuardVersionedEntity interface {
	GetID() int64
	GetVersion() uint64
}

// NewCreateWriteGuard 为单资源创建写入构造显式写边界。
func NewCreateWriteGuard(ctx context.Context, kind, tenantID string) (authz.WriteGuard, error) {
	return newWriteGuard(ctx, kind, strings.TrimSpace(tenantID), "", "", "", "")
}

// NewEntityWriteGuard 为已存在资源构造带 revision 的显式写边界。
func NewEntityWriteGuard(ctx context.Context, kind string, entity tenantVersionedEntity) (authz.WriteGuard, error) {
	if entity == nil {
		return authz.WriteGuard{}, errorx.New(errorx.InvalidInput, "entity is required")
	}
	return newWriteGuard(
		ctx,
		kind,
		strings.TrimSpace(entity.GetTenantID()),
		"",
		"",
		strconv.FormatInt(entity.GetID(), 10),
		strconv.FormatUint(entity.GetVersion(), 10),
	)
}

// NewPlatformCreateWriteGuard 为 platform-scoped 资源创建显式写边界。
func NewPlatformCreateWriteGuard(ctx context.Context, kind string) (authz.WriteGuard, error) {
	return newWriteGuard(ctx, kind, "", string(iammw.ScopePlatform), platformScopeCode, "", "")
}

// NewPlatformEntityWriteGuard 为已存在的 platform-scoped 资源构造带 revision 的显式写边界。
func NewPlatformEntityWriteGuard(ctx context.Context, kind string, entity writeGuardVersionedEntity) (authz.WriteGuard, error) {
	if entity == nil {
		return authz.WriteGuard{}, errorx.New(errorx.InvalidInput, "entity is required")
	}
	return newWriteGuard(
		ctx,
		kind,
		"",
		string(iammw.ScopePlatform),
		platformScopeCode,
		strconv.FormatInt(entity.GetID(), 10),
		strconv.FormatUint(entity.GetVersion(), 10),
	)
}

func newWriteGuard(ctx context.Context, kind, tenantID, scopeType, scopeCode, resourceID, revision string) (authz.WriteGuard, error) {
	_ = ctx
	kind = strings.TrimSpace(kind)
	tenantID = strings.TrimSpace(tenantID)
	scopeType = strings.TrimSpace(scopeType)
	scopeCode = strings.TrimSpace(scopeCode)
	resourceID = strings.TrimSpace(resourceID)
	revision = strings.TrimSpace(revision)
	if kind == "" {
		return authz.WriteGuard{}, errorx.New(errorx.InvalidInput, "resource kind is required")
	}
	if tenantID == "" && scopeType == "" && scopeCode == "" {
		return authz.WriteGuard{}, errorx.New(errorx.InvalidInput, "tenant_id or scope boundary is required for write guard")
	}
	resource := authz.Resource{
		Kind:      kind,
		ID:        resourceID,
		TenantID:  tenantID,
		ScopeType: scopeType,
		ScopeCode: scopeCode,
		Revision:  revision,
	}
	return authz.AllowDecision(resource).WriteGuard(), nil
}
