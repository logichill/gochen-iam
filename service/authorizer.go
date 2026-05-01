package service

import (
	"context"
	"strconv"
	"strings"

	iamaccess "gochen-iam/access"
	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	auth "gochen/auth"
	appaccess "gochen/auth/access"
	"gochen/contextx"
	"gochen/errors"
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
func NewIAMAuthorizer(scopeAuthorizer *ScopeAuthorizer, registry *auth.Registry) (*auth.Authorizer, error) {
	return auth.NewAuthorizer(
		auth.EvaluatorFunc(func(
			ctx context.Context,
			principal auth.Principal,
			permission string,
			resources []auth.Resource,
		) (auth.AuthzDecision, error) {
			return evaluateIAMAuthorization(ctx, scopeAuthorizer, principal, permission, resources)
		}),
		registry,
	)
}

// AuthorizeWriteConstraint 执行统一授权，并把 allow 决策投影成显式写约束。
func AuthorizeWriteConstraint(ctx context.Context, authorizer auth.IAuthorizer, permission string, targets ...any) (WriteConstraint, error) {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "permission is required")
	}
	if authorizer == nil {
		return WriteConstraint{}, errors.NewCode(errors.InvalidInput, "authorizer is required")
	}
	decision, err := authorizer.Authorize(ctx, permission, targets...)
	if err != nil {
		return WriteConstraint{}, err
	}
	if err := decision.RequireAllow(); err != nil {
		return WriteConstraint{}, err
	}
	return iamaccess.NewWriteConstraint(schemaSafeWriteConstraint(decision), appaccess.ConstraintMetadataFromDecision(decision)), nil
}

// AuthorizeCreateConstraint 为 create 路径构造写入约束。
func AuthorizeCreateConstraint(ctx context.Context, authorizer auth.IAuthorizer, permission string, targets ...any) (WriteConstraint, error) {
	constraint, err := AuthorizeWriteConstraint(ctx, authorizer, permission, targets...)
	if err != nil {
		return WriteConstraint{}, err
	}
	for i := range constraint.Resources {
		constraint.Resources[i].ResourceID = ""
		constraint.Resources[i].Revision = ""
	}
	return constraint, nil
}

// WithSystemPrincipal 为后台/内部任务构造统一的 system principal 运行时。
func WithSystemPrincipal(ctx context.Context, tenantID string, metadata auth.ExecutionMetadata) (context.Context, error) {
	ctx, err := auth.WithPrincipal(ctx, auth.Principal{
		IsSystem: true,
	})
	if err != nil {
		return nil, err
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		ctx, err = BindTenantContext(ctx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	replayCtx, _, err := auth.PrepareReplayAuthorization(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return replayCtx, nil
}

func evaluateIAMAuthorization(
	ctx context.Context,
	scopeAuthorizer *ScopeAuthorizer,
	principal auth.Principal,
	permission string,
	resources []auth.Resource,
) (auth.AuthzDecision, error) {
	resources = normalizeIAMAuthorizedResources(ctx, resources)
	if !principalHasPermission(principal, permission) {
		return auth.DenyDecision("permission_denied", resources...), nil
	}
	if requiresPlatformScope(resources) && !principalCanAccessPlatform(principal, ctx) {
		return auth.DenyDecision("platform_scope_denied", resources...), nil
	}

	targetTenantID, hasTenantBoundary, mixedTenantTargets := collectAuthorizedTenant(ctx, resources)
	if mixedTenantTargets {
		return auth.DenyDecision("cross_tenant_resource_set", resources...), nil
	}
	if !hasTenantBoundary {
		return auth.AllowDecision(resources...), nil
	}

	allowed, err := allowTenantAccess(ctx, scopeAuthorizer, principal, targetTenantID)
	if err != nil {
		return auth.AuthzDecision{}, err
	}
	if !allowed {
		return auth.DenyDecision("tenant_scope_denied", resources...), nil
	}

	return auth.AllowDecision(resources...), nil
}

func normalizeIAMAuthorizedResources(ctx context.Context, resources []auth.Resource) []auth.Resource {
	if len(resources) == 0 {
		return resources
	}
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	out := make([]auth.Resource, len(resources))
	copy(out, resources)
	for i := range out {
		if requiresPlatformScope([]auth.Resource{out[i]}) {
			out[i].GlobalScope = true
			out[i].ManagedScopeID = 0
			continue
		}
		if tenantID != "" {
			if out[i].TenantID == "" {
				out[i].TenantID = tenantID
			}
			if out[i].OwnerID == "" {
				out[i].OwnerID = tenantOwnerID(tenantID)
			}
		}
	}
	return out
}

func schemaSafeWriteConstraint(decision auth.AuthzDecision) appaccess.WriteConstraint {
	constraint := appaccess.WriteConstraintFromDecision(decision)
	for i := range constraint.Resources {
		if !resourceKindUsesManagedScope(constraint.Resources[i].Kind) {
			// 平台级资源显式标记 GlobalScope，避免与"未填充 ManagedScopeID"语义混淆。
			constraint.Resources[i].GlobalScope = true
			constraint.Resources[i].ManagedScopeID = 0
		}
	}
	return constraint
}

func resourceKindUsesManagedScope(kind string) bool {
	switch strings.TrimSpace(kind) {
	case UserResourceKind, GroupResourceKind, RoleResourceKind:
		return true
	default:
		return false
	}
}

func requiresPlatformScope(resources []auth.Resource) bool {
	for _, resource := range resources {
		switch strings.TrimSpace(resource.Kind) {
		case TenantResourceKind, MenuResourceKind, ScopeResourceKind:
			return true
		}
	}
	return false
}

func allowTenantAccess(
	ctx context.Context,
	scopeAuthorizer *ScopeAuthorizer,
	principal auth.Principal,
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
		// 明确语义的边界错误（租户不存在、跨租户、输入非法）映射为 not allowed；
		// 其他错误（如 DB 瞬时不可用）透传，避免被伪装成 "tenant_scope_denied"。
		if errors.Is(err, errors.NotFound) || errors.Is(err, errors.Forbidden) {
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
		if errors.Is(err, errors.NotFound) {
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
	principal auth.Principal,
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

	if strings.EqualFold(activeScopeKindFromContext(ctx), string(iammw.ScopePlatform)) {
		if targetTenantID == "" {
			return tenantAccessResolution{TenantID: strings.TrimSpace(contextx.TenantID(ctx))}, nil
		}
		return tenantAccessResolution{TenantID: targetTenantID}, nil
	}

	tenantID, err := tenant.NormalizeTenantID(ctx, targetTenantID)
	if err != nil {
		return tenantAccessResolution{}, err
	}
	if strings.TrimSpace(contextx.TenantID(ctx)) != tenantID {
		return tenantAccessResolution{}, errors.NewCode(errors.Forbidden, "cross-tenant access denied")
	}
	return tenantAccessResolution{TenantID: tenantID}, nil
}

func collectAuthorizedTenant(ctx context.Context, resources []auth.Resource) (tenantID string, hasTenantBoundary bool, mixed bool) {
	for _, resource := range resources {
		currentTenantID := tenantIDFromResource(resource)
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
	if !hasTenantBoundary {
		currentTenantID := strings.TrimSpace(contextx.TenantID(ctx))
		if currentTenantID != "" {
			return currentTenantID, true, false
		}
	}
	return tenantID, hasTenantBoundary, false
}

func resourceFromEntity(kind string, entity tenantVersionedEntity) (auth.Resource, bool) {
	if entity == nil {
		return auth.Resource{}, false
	}

	tenantID := strings.TrimSpace(entity.GetTenantID())
	resource := auth.Resource{
		Kind:     strings.TrimSpace(kind),
		TenantID: tenantID,
		OwnerID:  tenantOwnerID(tenantID),
	}
	if ownable, ok := any(entity).(interface{ GetOwnerID() string }); ok && strings.TrimSpace(ownable.GetOwnerID()) != "" {
		resource.OwnerID = strings.TrimSpace(ownable.GetOwnerID())
	}
	if scoped, ok := any(entity).(interface{ GetManagedScopeID() int64 }); ok && scoped.GetManagedScopeID() > 0 {
		resource.ManagedScopeID = scoped.GetManagedScopeID()
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

func platformResourceFromEntity(kind string, entity versionedEntity) (auth.Resource, bool) {
	resource := auth.Resource{
		Kind:        strings.TrimSpace(kind),
		GlobalScope: true,
	}
	if entity == nil {
		return auth.Resource{}, false
	}
	if entity.GetID() <= 0 {
		return resource, true
	}
	resource.ID = strconv.FormatInt(entity.GetID(), 10)
	resource.Revision = strconv.FormatUint(entity.GetVersion(), 10)
	return resource, true
}

func tenantIDFromResource(resource auth.Resource) string {
	if id := strings.TrimSpace(resource.TenantID); id != "" {
		return id
	}
	return ""
}
