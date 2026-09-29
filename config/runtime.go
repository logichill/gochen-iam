package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	iammw "gochen-iam/middleware"
	"gochen-iam/tenant"
	"gochen/httpx"
)

const (
	envAuthSecret          = "AUTH_SECRET"
	envAccessTokenTTL      = "AUTH_ACCESS_TOKEN_TTL"
	envAllowQueryToken     = "AUTH_ALLOW_QUERY_TOKEN"
	envRequireTenant       = "AUTH_REQUIRE_TENANT"
	envAllowTenantQuery    = "AUTH_ALLOW_TENANT_QUERY"
	envTenantHeader        = "AUTH_TENANT_HEADER"
	defaultAccessTokenTTL  = 24 * time.Hour
	defaultTenantHeaderKey = httpx.HeaderTenantID
	defaultTenantMode      = string(tenant.ModeSingle)
	defaultSingleTenantID  = tenant.DefaultSingleTenantID
)

// RuntimeConfig 描述 gochen-iam 运行期依赖的租户与鉴权配置。
type RuntimeConfig struct {
	TenantMode       string        `json:"tenant_mode" yaml:"tenant_mode" env:"IAM_TENANT_MODE" default:"single"`
	SingleTenantID   string        `json:"single_tenant_id" yaml:"single_tenant_id" env:"IAM_SINGLE_TENANT_ID" default:"default"`
	SecretKey        string        `json:"secret_key" yaml:"secret_key" env:"AUTH_SECRET"`
	AccessTokenTTL   time.Duration `json:"access_token_ttl" yaml:"access_token_ttl" env:"AUTH_ACCESS_TOKEN_TTL" default:"24h"`
	AllowQueryToken  bool          `json:"allow_query_token" yaml:"allow_query_token" env:"AUTH_ALLOW_QUERY_TOKEN"`
	RequireTenant    bool          `json:"require_tenant" yaml:"require_tenant" env:"AUTH_REQUIRE_TENANT"`
	AllowTenantQuery bool          `json:"allow_tenant_query" yaml:"allow_tenant_query" env:"AUTH_ALLOW_TENANT_QUERY"`
	TenantHeader     string        `json:"tenant_header" yaml:"tenant_header" env:"AUTH_TENANT_HEADER" default:"X-Tenant-ID"`
}

// NewAuthConfig 将 IAM 运行配置转换成可注入的认证配置。
//
// environment 来自应用配置，而不是进程环境；这样认证安全模式与应用配置保持同一
// 来源，组合根无需通过 os.Setenv 把结构化配置桥接回 IAM。
func NewAuthConfig(cfg *RuntimeConfig, environment string) *iammw.AuthConfig {
	cfg = NormalizeRuntimeConfig(cfg)
	authConfig := iammw.DefaultAuthConfigForEnvironment(environment)
	authConfig.SecretKey = cfg.SecretKey
	authConfig.AccessTokenTTL = cfg.AccessTokenTTL
	authConfig.AllowQueryToken = cfg.AllowQueryToken
	authConfig.RequireTenant = cfg.RequireTenant
	authConfig.AllowTenantQuery = cfg.AllowTenantQuery
	authConfig.TenantHeader = cfg.TenantHeader
	authConfig.TenantPolicy = tenant.NormalizePolicy(tenant.Policy{
		Mode:           tenant.Mode(cfg.TenantMode),
		SingleTenantID: cfg.SingleTenantID,
	})
	return authConfig
}

// DefaultRuntimeConfig 返回标准默认运行配置。
func DefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		TenantMode:       defaultTenantMode,
		SingleTenantID:   defaultSingleTenantID,
		SecretKey:        "",
		AccessTokenTTL:   defaultAccessTokenTTL,
		AllowQueryToken:  false,
		RequireTenant:    false,
		AllowTenantQuery: false,
		TenantHeader:     defaultTenantHeaderKey,
	}
}

// NormalizeRuntimeConfig 规范化运行配置并补齐默认值。
func NormalizeRuntimeConfig(cfg *RuntimeConfig) *RuntimeConfig {
	if cfg == nil {
		cfg = DefaultRuntimeConfig()
	}
	defaults := DefaultRuntimeConfig()

	cfg.TenantMode = strings.ToLower(strings.TrimSpace(cfg.TenantMode))
	if cfg.TenantMode == "" {
		cfg.TenantMode = defaults.TenantMode
	}

	cfg.SingleTenantID = strings.TrimSpace(cfg.SingleTenantID)
	if cfg.TenantMode == string(tenant.ModeSingle) && cfg.SingleTenantID == "" {
		cfg.SingleTenantID = defaults.SingleTenantID
	}

	cfg.SecretKey = strings.TrimSpace(cfg.SecretKey)
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = defaults.AccessTokenTTL
	}
	cfg.TenantHeader = strings.TrimSpace(cfg.TenantHeader)
	if cfg.TenantHeader == "" {
		cfg.TenantHeader = defaults.TenantHeader
	}

	return cfg
}

// ApplyEnvOverrides 用进程环境变量覆盖当前运行配置。
func ApplyEnvOverrides(cfg *RuntimeConfig) *RuntimeConfig {
	return ApplyEnvOverridesWithLookup(cfg, os.LookupEnv)
}

// ApplyEnvOverridesWithLookup 用指定 lookup 源覆盖当前运行配置。
func ApplyEnvOverridesWithLookup(cfg *RuntimeConfig, lookup func(string) (string, bool)) *RuntimeConfig {
	cfg = NormalizeRuntimeConfig(cfg)

	if value, ok := lookup(tenant.EnvTenantMode); ok && strings.TrimSpace(value) != "" {
		cfg.TenantMode = strings.ToLower(value)
	}
	if value, ok := lookup(tenant.EnvSingleTenantID); ok && strings.TrimSpace(value) != "" {
		cfg.SingleTenantID = value
	}
	if value, ok := lookup(envAuthSecret); ok && value != "" {
		cfg.SecretKey = strings.TrimSpace(value)
	}
	if value, ok := lookup(envAccessTokenTTL); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			cfg.AccessTokenTTL = parsed
		}
	}
	if value, ok := lookup(envAllowQueryToken); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.AllowQueryToken = parsed
		}
	}
	if value, ok := lookup(envRequireTenant); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.RequireTenant = parsed
		}
	}
	if value, ok := lookup(envAllowTenantQuery); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.AllowTenantQuery = parsed
		}
	}
	if value, ok := lookup(envTenantHeader); ok && strings.TrimSpace(value) != "" {
		value = strings.TrimSpace(value)
		cfg.TenantHeader = value
	}

	return NormalizeRuntimeConfig(cfg)
}

// ValidateRuntimeConfig 校验当前运行配置是否满足运行要求。
func ValidateRuntimeConfig(cfg *RuntimeConfig, appEnv string, authEnabled bool) error {
	cfg = NormalizeRuntimeConfig(cfg)

	switch cfg.TenantMode {
	case string(tenant.ModeSingle), string(tenant.ModeTenant):
	default:
		return fmt.Errorf("非法的 IAM tenant_mode: %s (必须是 single/tenant 之一)", cfg.TenantMode)
	}

	if cfg.TenantMode == string(tenant.ModeSingle) && strings.TrimSpace(cfg.SingleTenantID) == "" {
		return fmt.Errorf("IAM single 模式下必须配置 single_tenant_id")
	}

	if !isDevEnv(appEnv) && cfg.AllowQueryToken {
		return fmt.Errorf("生产环境禁止启用 AUTH_ALLOW_QUERY_TOKEN")
	}

	if authEnabled && isProdEnv(appEnv) && cfg.SecretKey == "" {
		return fmt.Errorf("生产环境必须配置 AUTH_SECRET 环境变量，禁止使用默认或空的 JWT 密钥")
	}

	return nil
}

func isDevEnv(appEnv string) bool {
	switch strings.ToLower(strings.TrimSpace(appEnv)) {
	case "development", "dev", "test", "testing":
		return true
	default:
		return false
	}
}

func isProdEnv(appEnv string) bool {
	return strings.EqualFold(strings.TrimSpace(appEnv), "production")
}
