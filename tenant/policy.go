package tenant

import (
	"context"
	"gochen/contextx"
	"gochen/errors"
	"strings"
)

type Mode string

const (
	ModeTenant Mode = "tenant"
	ModeSingle Mode = "single"

	EnvTenantMode     = "IAM_TENANT_MODE"
	EnvSingleTenantID = "IAM_SINGLE_TENANT_ID"

	DefaultSingleTenantID = "default"
)

type Policy struct {
	Mode           Mode
	SingleTenantID string
}

type policyContextKey struct{}

// NormalizePolicy 补齐并规范化租户策略。
func NormalizePolicy(policy Policy) Policy {
	policy.Mode = Mode(strings.ToLower(strings.TrimSpace(string(policy.Mode))))
	if policy.Mode != ModeTenant {
		policy.Mode = ModeSingle
	}
	policy.SingleTenantID = strings.TrimSpace(policy.SingleTenantID)
	if policy.Mode == ModeSingle && policy.SingleTenantID == "" {
		policy.SingleTenantID = DefaultSingleTenantID
	}
	return policy
}

// WithPolicy 将显式租户策略绑定到当前请求上下文。
func WithPolicy(ctx context.Context, policy Policy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, policyContextKey{}, NormalizePolicy(policy))
}

// PolicyFromContext 返回请求上下文中的显式租户策略。
func PolicyFromContext(ctx context.Context) (Policy, bool) {
	if ctx == nil {
		return Policy{}, false
	}
	policy, ok := ctx.Value(policyContextKey{}).(Policy)
	if !ok {
		return Policy{}, false
	}
	return NormalizePolicy(policy), true
}

// CurrentContext 返回请求上下文策略；未绑定时保留租户隔离，单租户模式必须显式绑定。
func CurrentContext(ctx context.Context) Policy {
	if policy, ok := PolicyFromContext(ctx); ok {
		return policy
	}
	return Policy{Mode: ModeTenant}
}

// Resolver 为仓储和框架 tenant wrapper 提供无全局状态的上下文解析策略。
type Resolver struct{}

// ResolveTenantID 从请求上下文解析 tenant；IAM 模式归一化由入口服务负责。
func (Resolver) ResolveTenantID(ctx context.Context) (string, error) {
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	if tenantID == "" {
		return "", errors.NewCode(errors.InvalidInput, "tenant ID is required in context")
	}
	return tenantID, nil
}

func (p Policy) IsSingle() bool {
	return p.Mode == ModeSingle
}

func ResolveTenantID(ctx context.Context) (string, error) {
	policy := CurrentContext(ctx)
	if policy.IsSingle() {
		return policy.SingleTenantID, nil
	}
	tenantID := strings.TrimSpace(contextx.TenantID(ctx))
	if tenantID == "" {
		return "", errors.NewCode(errors.Validation, "tenant_id is required")
	}
	return tenantID, nil
}

func NormalizeTenantID(ctx context.Context, targetTenantID string) (string, error) {
	tenantID, err := ResolveTenantID(ctx)
	if err != nil {
		return "", err
	}
	targetTenantID = strings.TrimSpace(targetTenantID)
	if targetTenantID == "" {
		return tenantID, nil
	}
	if targetTenantID != tenantID {
		return "", errors.NewCode(errors.Forbidden, "跨租户访问被拒绝")
	}
	return tenantID, nil
}

// ResolveRequestTenantIDWithPolicy 按显式租户策略决定本次请求应使用的 tenant。
func ResolveRequestTenantIDWithPolicy(policy Policy, requestTenantID, currentTenantID string, requireTenant bool) (string, error) {
	requestTenantID = strings.TrimSpace(requestTenantID)
	currentTenantID = strings.TrimSpace(currentTenantID)
	policy = NormalizePolicy(policy)

	if policy.IsSingle() {
		if requestTenantID != "" && requestTenantID != policy.SingleTenantID {
			return "", errors.NewCode(errors.Forbidden, "request tenant does not match configured tenant")
		}
		return policy.SingleTenantID, nil
	}

	if requestTenantID != "" {
		return requestTenantID, nil
	}
	if currentTenantID != "" {
		return currentTenantID, nil
	}
	if requireTenant {
		return "", errors.NewCode(errors.Validation, "tenant_id is required")
	}
	return "", nil
}
