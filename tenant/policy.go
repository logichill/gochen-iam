package tenant

import (
	"context"
	"os"
	"strings"

	ctxx "gochen/contextx"
	domaincrud "gochen/domain/crud"
	"gochen/errorx"
)

type Mode string

const (
	ModeTenant Mode = "tenant"
	ModeSingle Mode = "single"

	EnvTenantMode     = "IAM_TENANT_MODE"
	EnvSingleTenantID = "IAM_SINGLE_TENANT_ID"

	DefaultSingleTenantID = "default"
	activeScopePlatform   = "platform"
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
		return "", errorx.New(errorx.Validation, "tenant_id is required")
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
		return "", errorx.New(errorx.InvalidInput, "tenant ID is required in context")
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
		return "", errorx.New(errorx.Forbidden, "跨租户访问被拒绝")
	}
	return tenantID, nil
}

func ResolveRequestTenantID(requestTenantID, tokenTenantID string, requireTenant bool) (string, error) {
	return ResolveRequestTenantIDWithScope(requestTenantID, tokenTenantID, "", requireTenant)
}

// ResolveRequestTenantIDWithScope 按请求 tenant、token tenant 与 active scope 决定本次请求应使用的 tenant。
func ResolveRequestTenantIDWithScope(requestTenantID, tokenTenantID, activeScopeType string, requireTenant bool) (string, error) {
	requestTenantID = strings.TrimSpace(requestTenantID)
	tokenTenantID = strings.TrimSpace(tokenTenantID)
	activeScopeType = strings.TrimSpace(strings.ToLower(activeScopeType))

	policy := Current()
	if policy.IsSingle() {
		if requestTenantID != "" && requestTenantID != policy.SingleTenantID {
			return "", errorx.New(errorx.Forbidden, "request tenant does not match configured tenant")
		}
		if tokenTenantID != "" && tokenTenantID != policy.SingleTenantID {
			return "", errorx.New(errorx.Forbidden, "token tenant does not match configured tenant")
		}
		return policy.SingleTenantID, nil
	}

	if activeScopeType == activeScopePlatform && requestTenantID != "" {
		return requestTenantID, nil
	}
	if requestTenantID != "" && tokenTenantID != "" && requestTenantID != tokenTenantID {
		return "", errorx.New(errorx.Forbidden, "token tenant does not match request tenant")
	}
	if requestTenantID != "" {
		return requestTenantID, nil
	}
	if tokenTenantID != "" {
		return tokenTenantID, nil
	}
	if requireTenant {
		return "", errorx.New(errorx.Validation, "tenant_id is required")
	}
	return "", nil
}
