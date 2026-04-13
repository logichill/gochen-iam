package service

import (
	"context"
	"strconv"
	"strings"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	"gochen/authz"
	"gochen/errorx"
)

const (
	UserResourceKind   = "iam.user"
	GroupResourceKind  = "iam.group"
	RoleResourceKind   = "iam.role"
	TenantResourceKind = "iam.tenant"
	MenuResourceKind   = "iam.menu"
	ScopeResourceKind  = "iam.scope"
)

// NewIAMAuthorizer 创建 IAM 领域统一授权器：
// - 标准 CRUD 通过 route/builder 自动调用；
// - 自定义单资源/关联写路径也复用同一套 permission + tenant/scope 决策。
func NewIAMAuthorizer(scopeAuthorizer *ScopeAuthorizer) (*authz.Authorizer, error) {
	registry := authz.NewResourceRegistry(
		authz.TypedResourceResolver[*iamentity.User](func(target *iamentity.User) (authz.Resource, bool) {
			return resourceFromEntity(UserResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Group](func(target *iamentity.Group) (authz.Resource, bool) {
			return resourceFromEntity(GroupResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Role](func(target *iamentity.Role) (authz.Resource, bool) {
			return resourceFromEntity(RoleResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.Tenant](func(target *iamentity.Tenant) (authz.Resource, bool) {
			return platformResourceFromEntity(TenantResourceKind, target)
		}),
		authz.TypedResourceResolver[*iamentity.MenuItem](func(target *iamentity.MenuItem) (authz.Resource, bool) {
			return platformResourceFromEntity(MenuResourceKind, target)
		}),
	)

	return authz.NewAuthorizer(
		authz.EvaluatorFunc(func(
			ctx context.Context,
			principal authz.Principal,
			permission string,
			resources []authz.Resource,
		) (authz.AuthzDecision, error) {
			return evaluateIAMAuthorization(ctx, scopeAuthorizer, principal, permission, resources)
		}),
		registry,
	)
}

// AuthorizeWriteGuard 执行统一授权，并把 allow 决策投影成显式 WriteGuard。
func AuthorizeWriteGuard(ctx context.Context, authorizer authz.IAuthorizer, permission string, targets ...any) (authz.WriteGuard, error) {
	if authorizer == nil {
		return authz.WriteGuard{}, errorx.New(errorx.InvalidInput, "authorizer is required")
	}
	decision, err := authorizer.Authorize(ctx, permission, targets...)
	if err != nil {
		return authz.WriteGuard{}, err
	}
	if err := decision.RequireAllow(); err != nil {
		return authz.WriteGuard{}, err
	}
	return decision.WriteGuard(), nil
}

// WithSystemPrincipal 为后台/内部任务构造统一的 system principal 运行时。
func WithSystemPrincipal(ctx context.Context, tenantID string, metadata authz.ExecutionMetadata) (context.Context, error) {
	ctx, err := authz.WithPrincipal(ctx, authz.Principal{
		IsSystem: true,
		TenantID: strings.TrimSpace(tenantID),
	})
	if err != nil {
		return nil, err
	}
	replayCtx, _, err := authz.PrepareReplayAuthorization(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return replayCtx, nil
}

func evaluateIAMAuthorization(
	ctx context.Context,
	scopeAuthorizer *ScopeAuthorizer,
	principal authz.Principal,
	permission string,
	resources []authz.Resource,
) (authz.AuthzDecision, error) {
	if !principalHasPermission(principal, permission) {
		return authz.DenyDecision("permission_denied", resources...), nil
	}
	if requiresPlatformScope(resources) && !principalCanAccessPlatform(principal) {
		return authz.DenyDecision("platform_scope_denied", resources...), nil
	}

	targetTenantID, hasTenantBoundary, mixedTenantTargets := collectAuthorizedTenant(resources)
	if mixedTenantTargets {
		return authz.DenyDecision("cross_tenant_resource_set", resources...), nil
	}
	if !hasTenantBoundary {
		return authz.AllowDecision(resources...), nil
	}

	allowed, err := allowTenantAccess(ctx, scopeAuthorizer, principal, targetTenantID)
	if err != nil {
		return authz.AuthzDecision{}, err
	}
	if !allowed {
		return authz.DenyDecision("tenant_scope_denied", resources...), nil
	}

	return authz.AllowDecision(resources...), nil
}

func requiresPlatformScope(resources []authz.Resource) bool {
	for _, resource := range resources {
		if strings.EqualFold(strings.TrimSpace(resource.ScopeType), string(iammw.ScopePlatform)) {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(resource.ScopeCode), platformScopeCode) {
			return true
		}
	}
	return false
}

func allowTenantAccess(
	ctx context.Context,
	scopeAuthorizer *ScopeAuthorizer,
	principal authz.Principal,
	targetTenantID string,
) (bool, error) {
	targetTenantID = strings.TrimSpace(targetTenantID)
	if targetTenantID == "" {
		return true, nil
	}
	if principal.IsSystem {
		return true, nil
	}

	resolution, err := resolveTenantAccessForPrincipal(ctx, principal, targetTenantID)
	if err != nil {
		if errorx.Is(err, errorx.Forbidden) || errorx.Is(err, errorx.Validation) || errorx.Is(err, errorx.Unauthorized) {
			return false, nil
		}
		return false, err
	}
	if resolution.SkipScopeCheck || scopeAuthorizer == nil || principal.ActiveScopeID <= 0 {
		return true, nil
	}

	scopeCtx, err := BindTenantContext(ctx, resolution.TenantID)
	if err != nil {
		return false, err
	}
	targetScope, err := scopeAuthorizer.ResolveTenantScope(scopeCtx, resolution.TenantID)
	if err != nil {
		if errorx.Is(err, errorx.NotFound) || errorx.Is(err, errorx.Forbidden) || errorx.Is(err, errorx.Validation) {
			return false, nil
		}
		return false, err
	}
	covers, err := scopeAuthorizer.ScopeCovers(ctx, principal.ActiveScopeID, targetScope.ID)
	if err != nil {
		return false, err
	}
	return covers, nil
}

func resolveTenantAccessForPrincipal(
	ctx context.Context,
	principal authz.Principal,
	targetTenantID string,
) (tenantAccessResolution, error) {
	targetTenantID = strings.TrimSpace(targetTenantID)

	if tenant.Current().IsSingle() {
		tenantID, err := tenant.NormalizeTenantID(ctx, targetTenantID)
		if err != nil {
			return tenantAccessResolution{}, err
		}
		return tenantAccessResolution{
			TenantID:       tenantID,
			SkipScopeCheck: true,
		}, nil
	}

	if strings.EqualFold(strings.TrimSpace(principal.ActiveScopeType), string(iammw.ScopePlatform)) {
		if targetTenantID == "" {
			return tenantAccessResolution{TenantID: strings.TrimSpace(principal.TenantID)}, nil
		}
		return tenantAccessResolution{TenantID: targetTenantID}, nil
	}

	tenantID, err := tenant.NormalizeTenantID(ctx, targetTenantID)
	if err != nil {
		return tenantAccessResolution{}, err
	}
	if strings.TrimSpace(principal.TenantID) != tenantID {
		return tenantAccessResolution{}, errorx.New(errorx.Forbidden, "cross-tenant access denied")
	}
	return tenantAccessResolution{TenantID: tenantID}, nil
}

func collectAuthorizedTenant(resources []authz.Resource) (tenantID string, hasTenantBoundary bool, mixed bool) {
	for _, resource := range resources {
		currentTenantID := strings.TrimSpace(resource.TenantID)
		if currentTenantID == "" {
			continue
		}
		if !hasTenantBoundary {
			tenantID = currentTenantID
			hasTenantBoundary = true
			continue
		}
		if tenantID != currentTenantID {
			return "", true, true
		}
	}
	return tenantID, hasTenantBoundary, false
}

func resourceFromEntity(kind string, entity tenantVersionedEntity) (authz.Resource, bool) {
	if entity == nil {
		return authz.Resource{}, false
	}

	resource := authz.Resource{
		Kind:     strings.TrimSpace(kind),
		TenantID: strings.TrimSpace(entity.GetTenantID()),
	}
	if scoped, ok := any(entity).(interface {
		GetScopeType() string
		GetScopeCode() string
	}); ok {
		resource.ScopeType = strings.TrimSpace(scoped.GetScopeType())
		resource.ScopeCode = strings.TrimSpace(scoped.GetScopeCode())
	}
	if entity.GetID() <= 0 {
		return resource, true
	}

	resource.ID = strconv.FormatInt(entity.GetID(), 10)
	resource.Revision = strconv.FormatUint(entity.GetVersion(), 10)
	return resource, true
}

type versionedEntity interface {
	GetID() int64
	GetVersion() uint64
}

func platformResourceFromEntity(kind string, entity versionedEntity) (authz.Resource, bool) {
	resource := authz.Resource{
		Kind:      strings.TrimSpace(kind),
		ScopeType: string(iammw.ScopePlatform),
		ScopeCode: platformScopeCode,
	}
	if entity == nil {
		return authz.Resource{}, false
	}
	if entity.GetID() <= 0 {
		return resource, true
	}
	resource.ID = strconv.FormatInt(entity.GetID(), 10)
	resource.Revision = strconv.FormatUint(entity.GetVersion(), 10)
	return resource, true
}
