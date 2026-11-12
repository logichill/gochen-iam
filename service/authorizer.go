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

// IAMAccess 是 IAM 领域唯一授权器：
//   - 标准 CRUD 通过 Application 按 auth.Request 调用；
//   - 自定义命令通过 AuthorizeTargets 复用同一套权限、租户与数据范围判定；
//   - 判定结果统一投影为 spec.Spec，由仓储在执行期解释，不再携带写约束。
type IAMAccess struct {
	checker         coreauth.IActionChecker
	scopeAuthorizer *ScopeAuthorizer
}

// NewIAMAccess 创建 IAM 领域授权器。
func NewIAMAccess(scopeAuthorizer *ScopeAuthorizer) *IAMAccess {
	return &IAMAccess{
		checker:         auth.NewActionChecker(),
		scopeAuthorizer: scopeAuthorizer,
	}
}

// Compile 以资源动作和已有元数据编译 IAM 平台、租户与范围约束。
func (a *IAMAccess) Compile(descriptor coreauth.Descriptor, metadata *meta.Metadata, entryConstraints ...coreauth.IPolicy) (*coreauth.Authorizer, error) {
	if a == nil {
		return nil, errors.NewCode(errors.InvalidInput, "IAM access declarations are required")
	}
	constraint := &targetPolicy{scopeAuthorizer: a.scopeAuthorizer, targets: []authorizationTarget{targetFromResourceKind(descriptor.Resource)}}
	// Entry guards run before tenant-scope policies that may load trusted facts.
	constraints := append(append([]coreauth.IPolicy(nil), entryConstraints...), constraint)
	return coreauth.Compile(coreauth.Declaration{Descriptor: descriptor, ResourceAccess: coreauth.ResourceAccessData, Rules: []coreauth.Rule{{ID: "iam." + descriptor.Resource + ".access", System: coreauth.SystemCheckConstraints, UnauthorizedAsDenial: true, Constraints: constraints}}}, coreauth.CompileOptions{Checker: a.checker, Metadata: metadata})
}

// AuthorizeTargets 对自定义命令的目标实体执行判定。
func (a *IAMAccess) AuthorizeTargets(ctx context.Context, permission string, targets ...any) (coreauth.Decision, error) {
	resolved := make([]authorizationTarget, 0, len(targets))
	for _, target := range targets {
		entry, ok := authorizationTargetFrom(target)
		if ok {
			resolved = append(resolved, entry)
		}
	}
	return a.decide(ctx, permission, resolved)
}

func (a *IAMAccess) decide(ctx context.Context, permission string, targets []authorizationTarget) (coreauth.Decision, error) {
	permission = strings.TrimSpace(permission)
	if permission == "" {
		return coreauth.Decision{}, errors.NewCode(errors.InvalidInput, "permission is required")
	}
	permissionPolicy, err := coreauth.NewPermissionPolicy(a.checker, coreauth.WithPermissionDenial("forbidden", true), coreauth.WithSystemConstraints())
	if err != nil {
		return coreauth.Decision{}, err
	}
	policy, err := coreauth.AllPolicies(permissionPolicy, &targetPolicy{scopeAuthorizer: a.scopeAuthorizer, targets: targets})
	if err != nil {
		return coreauth.Decision{}, err
	}
	authorizer, err := coreauth.New(coreauth.Options{Policy: policy})
	if err != nil {
		return coreauth.Decision{}, err
	}
	return authorizer.Authorize(ctx, coreauth.Request{Permission: permission})
}

// targetPolicy 是 IAM 平台与租户规则的特殊扩展，权限检查由通用内核执行。
type targetPolicy struct {
	scopeAuthorizer *ScopeAuthorizer
	targets         []authorizationTarget
}

func (a *targetPolicy) Vocabulary() coreauth.Vocabulary {
	if !hasManagedTarget(a.targets) {
		return coreauth.Vocabulary{}
	}
	return coreauth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (a *targetPolicy) Evaluate(ctx context.Context, _ coreauth.Request) (coreauth.Decision, error) {
	principal, _ := auth.PrincipalFromContext(ctx)
	if requiresPlatformScope(a.targets) && !principalCanAccessPlatform(principal, ctx) {
		return coreauth.Decision{Reason: ReasonPlatformScopeDenied}, nil
	}
	targetTenantID, hasTenantBoundary, mixedTenantTargets := collectAuthorizedTenant(ctx, a.targets)
	if mixedTenantTargets {
		return coreauth.Decision{Reason: ReasonCrossTenantDenied}, nil
	}
	if hasTenantBoundary {
		allowed, err := allowTenantAccess(ctx, a.scopeAuthorizer, principal, targetTenantID)
		if err != nil {
			return coreauth.Decision{}, err
		}
		if !allowed {
			return coreauth.Decision{Reason: ReasonTenantScopeDenied}, nil
		}
	}
	condition := spec.All()
	if !principal.IsSystem && hasManagedTarget(a.targets) {
		condition = DataScopeSpec(ctx)
	}
	return coreauth.Decision{Allowed: true, Spec: condition}, nil
}

// RequireAuthorization 对目标资源执行统一授权，适用于不需要写规约的读取路径。
func RequireAuthorization(ctx context.Context, authorizer *IAMAccess, permission string, targets ...any) error {
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
func AuthorizeWriteSpec(ctx context.Context, authorizer *IAMAccess, permission string, targets ...any) (spec.Spec, error) {
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
	case "tenant", TenantResourceKind:
		return platformTarget(TenantResourceKind)
	case "menu", MenuResourceKind:
		return platformTarget(MenuResourceKind)
	case "scope", ScopeResourceKind:
		return platformTarget(ScopeResourceKind)
	case "user", UserResourceKind:
		return managedTarget(UserResourceKind, "")
	case "group", GroupResourceKind:
		return managedTarget(GroupResourceKind, "")
	case "role", RoleResourceKind:
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
