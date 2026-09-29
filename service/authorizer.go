package service

import (
	"context"
	"strconv"
	"strings"

	iamaccess "gochen-iam/access"
	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
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

// 扩展拒绝原因码，细化排障与审计。
const (
	ReasonPlatformScopeDenied = "platform_scope_denied"
	ReasonCrossTenantDenied   = "cross_tenant_denied"
	ReasonTenantScopeDenied   = "tenant_scope_denied"
)

// DefaultDataScopeResolver 为 IAM 仓储与路由提供默认数据范围解析，直接复用底层统一事实源。
var DefaultDataScopeResolver = iamauth.DefaultDataScopeResolver

// NewIAMAuthorizer 创建 IAM 领域统一授权器：
// - 标准 CRUD 通过 route/builder 自动调用；
// - 自定义单资源/关联写路径也复用同一套 permission + tenant/scope 决策。
func NewIAMAuthorizer(scopeAuthorizer *ScopeAuthorizer, registry scoped.IResourceResolver) (scoped.IAuthorizer, error) {
	evaluator := scoped.EvaluatorFunc(func(
		ctx context.Context,
		permission string,
		resources []scoped.Resource,
	) (scoped.Decision, error) {
		principal, _ := auth.PrincipalFromContext(ctx)
		return evaluateIAMAuthorization(ctx, scopeAuthorizer, principal, permission, resources)
	})
	return scoped.NewAuthorizer(registry, evaluator)
}

// RequireAuthorization 对目标资源执行统一授权，适用于不需要写约束的读取路径。
func RequireAuthorization(ctx context.Context, authorizer scoped.IAuthorizer, permission string, targets ...any) error {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return errors.NewCode(errors.InvalidInput, "permission is required")
	}
	if authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "authorizer is required")
	}
	decision, err := authorizer.Authorize(ctx, permission, targets...)
	if err != nil {
		return err
	}
	if !decision.IsAllowed() {
		return errors.NewCode(errors.Forbidden, "authorization denied: "+decision.ReasonCode)
	}
	return nil
}

// AuthorizeWriteConstraint 执行统一授权，并把 allow 决策投影成显式写约束。
func AuthorizeWriteConstraint(ctx context.Context, authorizer scoped.IAuthorizer, permission string, targets ...any) (WriteConstraint, error) {
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
	if !decision.IsAllowed() {
		return WriteConstraint{}, errors.NewCode(errors.Forbidden, "authorization denied: "+decision.ReasonCode)
	}
	return iamaccess.NewWriteConstraint(schemaSafeWriteConstraint(decision)), nil
}

// AuthorizeCreateConstraint 为 create 路径构造写入约束。
func AuthorizeCreateConstraint(ctx context.Context, authorizer scoped.IAuthorizer, permission string, targets ...any) (WriteConstraint, error) {
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
func WithSystemPrincipal(ctx context.Context, tenantID string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	return ctx, nil
}

func evaluateIAMAuthorization(
	ctx context.Context,
	scopeAuthorizer *ScopeAuthorizer,
	principal auth.Principal,
	permission string,
	resources []scoped.Resource,
) (scoped.Decision, error) {
	resources = normalizeIAMAuthorizedResources(ctx, resources)
	if !principal.AllowsPermission(permission) {
		return scoped.Deny(scoped.ReasonActionDenied), nil
	}
	if requiresPlatformScope(resources) && !principalCanAccessPlatform(principal, ctx) {
		return scoped.Deny(ReasonPlatformScopeDenied), nil
	}

	targetTenantID, hasTenantBoundary, mixedTenantTargets := collectAuthorizedTenant(ctx, resources)
	if mixedTenantTargets {
		return scoped.Deny(ReasonCrossTenantDenied), nil
	}
	if !hasTenantBoundary {
		return scoped.Allow(resources...), nil
	}

	allowed, err := allowTenantAccess(ctx, scopeAuthorizer, principal, targetTenantID)
	if err != nil {
		return scoped.Decision{}, err
	}
	if !allowed {
		return scoped.Deny(ReasonTenantScopeDenied), nil
	}

	return scoped.Allow(resources...), nil
}

func normalizeIAMAuthorizedResources(ctx context.Context, resources []scoped.Resource) []scoped.Resource {
	if len(resources) == 0 {
		return resources
	}
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	out := make([]scoped.Resource, len(resources))
	copy(out, resources)
	for i := range out {
		if requiresPlatformScope([]scoped.Resource{out[i]}) {
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

func schemaSafeWriteConstraint(decision scoped.Decision) scoped.WriteConstraint {
	constraint := decision.WriteConstraint()
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

func requiresPlatformScope(resources []scoped.Resource) bool {
	for _, resource := range resources {
		if strings.EqualFold(strings.TrimSpace(resource.OwnerID), string(iammw.ScopePlatform)) {
			return true
		}
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

	if tenant.CurrentContext(ctx).IsSingle() {
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

func collectAuthorizedTenant(ctx context.Context, resources []scoped.Resource) (tenantID string, hasTenantBoundary bool, mixed bool) {
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

func resourceFromEntity(kind string, entity tenantVersionedEntity) (scoped.Resource, bool) {
	if entity == nil {
		return scoped.Resource{}, false
	}

	tenantID := strings.TrimSpace(entity.GetTenantID())
	resource := scoped.Resource{
		Kind:     strings.TrimSpace(kind),
		TenantID: tenantID,
		OwnerID:  tenantOwnerID(tenantID),
	}
	if ownable, ok := any(entity).(interface{ GetOwnerID() string }); ok && strings.TrimSpace(ownable.GetOwnerID()) != "" {
		resource.OwnerID = strings.TrimSpace(ownable.GetOwnerID())
	}
	if scopedVal, ok := any(entity).(interface{ GetManagedScopeID() int64 }); ok && scopedVal.GetManagedScopeID() > 0 {
		resource.ManagedScopeID = scopedVal.GetManagedScopeID()
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

func platformResourceFromEntity(kind string, entity versionedEntity) (scoped.Resource, bool) {
	resource := scoped.Resource{
		Kind:        strings.TrimSpace(kind),
		GlobalScope: true,
	}
	if entity == nil {
		return scoped.Resource{}, false
	}
	if entity.GetID() <= 0 {
		return resource, true
	}
	resource.ID = strconv.FormatInt(entity.GetID(), 10)
	resource.Revision = strconv.FormatUint(entity.GetVersion(), 10)
	return resource, true
}

func tenantIDFromResource(resource scoped.Resource) string {
	if id := strings.TrimSpace(resource.TenantID); id != "" {
		return id
	}
	return ""
}
