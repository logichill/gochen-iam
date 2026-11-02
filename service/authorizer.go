package service

import (
	"context"
	"gochen/domain/meta"
	"strings"

	iamentity "gochen-iam/entity"

	iamperm "gochen-iam/permissions"
	"gochen-iam/tenant"

	auth "gochen-runtime/host/authz"

	coreauth "gochen/auth"
	"gochen/auth/action"
	"gochen/contextx"
	"gochen/domain/spec"
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

// IAMAuthorizer 是 IAM 领域唯一授权器：
//   - 标准 CRUD 通过 Application 按 auth.Request 调用；
//   - 自定义命令通过 AuthorizeTargets 复用同一套权限、租户与数据范围判定；
//   - 判定结果统一投影为 spec.Spec，由仓储在执行期解释，不再携带写约束。
type IAMAuthorizer struct {
	checker         action.IActionChecker
	scopeAuthorizer *ScopeAuthorizer
	resource        string
}

// NewIAMAuthorizer 创建 IAM 领域授权器。
func NewIAMAuthorizer(scopeAuthorizer *ScopeAuthorizer) *IAMAuthorizer {
	return &IAMAuthorizer{
		checker:         auth.NewActionChecker(),
		scopeAuthorizer: scopeAuthorizer,
	}
}

// Vocabulary 声明判定结果可能引用的角色。
func (a *IAMAuthorizer) Vocabulary() coreauth.Vocabulary {
	if a.resource != "" && targetFromResourceKind(a.resource).platform {
		return coreauth.Vocabulary{}
	}
	return coreauth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}

// ForResource 固定 Application 使用的资源与授权词汇。
func (a *IAMAuthorizer) ForResource(resource string) coreauth.IAuthorizer {
	return &IAMAuthorizer{checker: a.checker, scopeAuthorizer: a.scopeAuthorizer, resource: resource}
}

// Authorize 按标准 CRUD 请求判定，返回调用方可直接传给仓储的规约。
func (a *IAMAuthorizer) Authorize(ctx context.Context, req coreauth.Request) (coreauth.Decision, error) {
	if a.resource != "" && a.resource != req.Resource {
		return coreauth.Decision{}, errors.NewCode(errors.Internal, "authorizer resource does not match request")
	}
	targets := []authorizationTarget{targetFromResourceKind(req.Resource)}
	return a.decide(ctx, req.Permission, targets)
}

// AuthorizeTargets 对自定义命令的目标实体执行判定。
func (a *IAMAuthorizer) AuthorizeTargets(ctx context.Context, permission string, targets ...any) (coreauth.Decision, error) {
	resolved := make([]authorizationTarget, 0, len(targets))
	for _, target := range targets {
		entry, ok := authorizationTargetFrom(target)
		if ok {
			resolved = append(resolved, entry)
		}
	}
	return a.decide(ctx, permission, resolved)
}

func (a *IAMAuthorizer) decide(ctx context.Context, permission string, targets []authorizationTarget) (coreauth.Decision, error) {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return coreauth.Decision{}, errors.NewCode(errors.InvalidInput, "permission is required")
	}
	principal, _ := auth.PrincipalFromContext(ctx)
	if !principal.IsSystem {
		if err := action.RequireAction(ctx, a.checker, permission); err != nil {
			if errors.Is(err, errors.Forbidden) || errors.Is(err, errors.Unauthorized) {
				return coreauth.Decision{Allowed: false, Reason: "forbidden"}, nil
			}
			return coreauth.Decision{}, err
		}
	}
	if requiresPlatformScope(targets) && !principalCanAccessPlatform(principal, ctx) {
		return coreauth.Decision{Allowed: false, Reason: ReasonPlatformScopeDenied}, nil
	}

	targetTenantID, hasTenantBoundary, mixedTenantTargets := collectAuthorizedTenant(ctx, targets)
	if mixedTenantTargets {
		return coreauth.Decision{Allowed: false, Reason: ReasonCrossTenantDenied}, nil
	}
	if hasTenantBoundary {
		allowed, err := allowTenantAccess(ctx, a.scopeAuthorizer, principal, targetTenantID)
		if err != nil {
			return coreauth.Decision{}, err
		}
		if !allowed {
			return coreauth.Decision{Allowed: false, Reason: ReasonTenantScopeDenied}, nil
		}
	}
	return coreauth.Decision{Allowed: true, Spec: a.specFor(ctx, targets, principal)}, nil
}

func (a *IAMAuthorizer) specFor(ctx context.Context, targets []authorizationTarget, principal auth.Principal) spec.Spec {
	if principal.IsSystem {
		return spec.All()
	}
	if len(targets) == 0 || !hasManagedTarget(targets) {
		return spec.All()
	}
	return DataScopeSpec(ctx)
}

// RequireAuthorization 对目标资源执行统一授权，适用于不需要写规约的读取路径。
func RequireAuthorization(ctx context.Context, authorizer *IAMAuthorizer, permission string, targets ...any) error {
	if authorizer == nil {
		return errors.NewCode(errors.InvalidInput, "authorizer is required")
	}
	decision, err := authorizer.AuthorizeTargets(ctx, permission, targets...)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return errors.NewCode(errors.Forbidden, "authorization denied: "+decision.Reason)
	}
	return nil
}

// AuthorizeWriteSpec 执行统一授权，并返回仓储写路径使用的行级规约。
func AuthorizeWriteSpec(ctx context.Context, authorizer *IAMAuthorizer, permission string, targets ...any) (spec.Spec, error) {
	if authorizer == nil {
		return spec.Spec{}, errors.NewCode(errors.InvalidInput, "authorizer is required")
	}
	decision, err := authorizer.AuthorizeTargets(ctx, permission, targets...)
	if err != nil {
		return spec.Spec{}, err
	}
	if !decision.Allowed {
		return spec.Spec{}, errors.NewCode(errors.Forbidden, "authorization denied: "+decision.Reason)
	}
	return decision.Spec, nil
}

// WithSystemPrincipal 为后台/内部任务构造统一的 system principal 运行时。
func WithSystemPrincipal(ctx context.Context, tenantID string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		var err error
		ctx, err = BindTenantContext(ctx, tenantID)
		if err != nil {
			return nil, err
		}
	}
	return auth.WithPrincipal(ctx, auth.Principal{IsSystem: true})
}

// authorizationTarget 是判定所需的最小资源事实。
type authorizationTarget struct {
	kind     string
	tenantID string
	platform bool
}

func managedTarget(kind, tenantID string) authorizationTarget {
	return authorizationTarget{kind: strings.TrimSpace(kind), tenantID: strings.TrimSpace(tenantID)}
}

func platformTarget(kind string) authorizationTarget {
	return authorizationTarget{kind: strings.TrimSpace(kind), platform: true}
}

func targetFromResourceKind(resource string) authorizationTarget {
	resource = strings.ToLower(strings.TrimSpace(resource))
	switch resource {
	case "tenant":
		return platformTarget(TenantResourceKind)
	case "menu":
		return platformTarget(MenuResourceKind)
	case "scope":
		return platformTarget(ScopeResourceKind)
	case "user":
		return managedTarget(UserResourceKind, "")
	case "group":
		return managedTarget(GroupResourceKind, "")
	case "role":
		return managedTarget(RoleResourceKind, "")
	default:
		return authorizationTarget{kind: resource}
	}
}

func authorizationTargetFrom(target any) (authorizationTarget, bool) {
	switch entity := target.(type) {
	case *iamentity.User:
		if entity == nil {
			return authorizationTarget{}, false
		}
		return managedTarget(UserResourceKind, entity.GetTenantID()), true
	case *iamentity.Group:
		if entity == nil {
			return authorizationTarget{}, false
		}
		return managedTarget(GroupResourceKind, entity.GetTenantID()), true
	case *iamentity.Role:
		if entity == nil {
			return authorizationTarget{}, false
		}
		// 平台自有角色只在 platform 授权域内可管理。
		if strings.EqualFold(strings.TrimSpace(entity.GetOwnerID()), string(iamperm.ScopePlatform)) {
			return platformTarget(RoleResourceKind), true
		}
		return managedTarget(RoleResourceKind, entity.GetTenantID()), true
	case *iamentity.Tenant:
		if entity == nil {
			return authorizationTarget{}, false
		}
		return platformTarget(TenantResourceKind), true
	case *iamentity.MenuItem:
		if entity == nil {
			return authorizationTarget{}, false
		}
		return platformTarget(MenuResourceKind), true
	case *iamentity.Scope:
		if entity == nil {
			return authorizationTarget{}, false
		}
		return platformTarget(ScopeResourceKind), true
	default:
		return authorizationTarget{}, false
	}
}

func hasManagedTarget(targets []authorizationTarget) bool {
	for _, target := range targets {
		if !target.platform {
			return true
		}
	}
	return false
}

func requiresPlatformScope(targets []authorizationTarget) bool {
	for _, target := range targets {
		if target.platform {
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
	if resolution.SkipScopeCheck {
		return true, nil
	}
	if scopeAuthorizer == nil {
		return false, errors.NewCode(errors.Internal, "scope authorizer is required for tenant scope verification")
	}
	if principal.ActiveScopeID <= 0 {
		return false, nil
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

	if strings.EqualFold(activeScopeKindFromContext(ctx), string(iamperm.ScopePlatform)) {
		if targetTenantID == "" {
			return tenantAccessResolution{
				TenantID:       strings.TrimSpace(contextx.TenantID(ctx)),
				SkipScopeCheck: true,
			}, nil
		}
		return tenantAccessResolution{
			TenantID:       targetTenantID,
			SkipScopeCheck: true,
		}, nil
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

func collectAuthorizedTenant(ctx context.Context, targets []authorizationTarget) (tenantID string, hasTenantBoundary bool, mixed bool) {
	for _, target := range targets {
		currentTenantID := strings.TrimSpace(target.tenantID)
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
