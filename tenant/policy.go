package tenant

import (
	"context"
	"os"
	"strings"

	ctxx "gochen/contextx"
	domaincrud "gochen/domain/crud"
	"gochen/errors"
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

// InstallTenantResolver 由组合根显式安装 CRUD tenant 解析策略。
func InstallTenantResolver() {
	domaincrud.SetTenantResolver(domaincrud.TenantResolverFunc(ResolveTenantIDForFramework))
}

func singlePolicy() Policy {
	singleTenantID := strings.TrimSpace(os.Getenv(EnvSingleTenantID))
	if singleTenantID == "" {
		singleTenantID = DefaultSingleTenantID
	}
	return Policy{
		Mode:           ModeSingle,
		SingleTenantID: singleTenantID,
	}
}

func Current() Policy {
	rawMode := strings.TrimSpace(strings.ToLower(os.Getenv(EnvTenantMode)))
	switch Mode(rawMode) {
	case ModeTenant:
		return Policy{Mode: ModeTenant}
	case "", ModeSingle:
		return singlePolicy()
	default:
		return singlePolicy()
	}
}

func (p Policy) IsSingle() bool {
	return p.Mode == ModeSingle
}

func ResolveTenantID(ctx context.Context) (string, error) {
	policy := Current()
	if policy.IsSingle() {
		return policy.SingleTenantID, nil
	}
	tenantID := strings.TrimSpace(ctxx.TenantID(ctx))
	if tenantID == "" {
		return "", errors.NewCode(errors.Validation, "tenant_id is required")
	}
	return tenantID, nil
}

func ResolveTenantIDForFramework(ctx context.Context) (string, error) {
	policy := Current()
	if policy.IsSingle() {
		return policy.SingleTenantID, nil
	}
	tenantID := strings.TrimSpace(ctxx.TenantID(ctx))
	if tenantID == "" {
		return "", errors.NewCode(errors.InvalidInput, "tenant ID is required in context")
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

// ResolveRequestTenantID 按请求 tenant / 当前上下文 tenant 决定本次请求应使用的 tenant。
func ResolveRequestTenantID(requestTenantID, currentTenantID string, requireTenant bool) (string, error) {
	requestTenantID = strings.TrimSpace(requestTenantID)
	currentTenantID = strings.TrimSpace(currentTenantID)

	policy := Current()
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
