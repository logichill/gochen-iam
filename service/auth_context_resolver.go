package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	iammw "gochen-iam/middleware"
	"gochen/errors"
)

// AuthContextResolverCacheTTL 控制 AuthContextResolver 的 binding 级缓存 TTL。
//
// 命中条件：相同 (active_scope_id, binding_version) 组合；未命中时回源
// ScopeAuthorizer 的 scope/visibility 查询。设置为 0 表示禁用缓存。
const AuthContextResolverCacheTTL = 30 * time.Second

// AuthContextResolver 将 access token claims 还原为运行时可消费的 scope 边界。
type AuthContextResolver struct {
	scopeAuthorizer *ScopeAuthorizer
	cacheTTL        time.Duration
	now             func() time.Time

	mu    sync.RWMutex
	cache map[string]authContextCacheEntry
}

type authContextCacheEntry struct {
	resolved  iammw.ResolvedAuthContext
	expiresAt time.Time
}

// AuthContextResolverInstaller 仅用于把 resolver 注册进 middleware 运行时。
type AuthContextResolverInstaller struct{}

func NewAuthContextResolver(scopeAuthorizer *ScopeAuthorizer) *AuthContextResolver {
	resolver := &AuthContextResolver{
		scopeAuthorizer: scopeAuthorizer,
		cacheTTL:        AuthContextResolverCacheTTL,
		now:             time.Now,
		cache:           make(map[string]authContextCacheEntry),
	}
	iammw.InstallAuthContextResolver(resolver)
	return resolver
}

func (r *AuthContextResolver) ResolveAuthContext(ctx context.Context, claims *iammw.JWTClaims) (*iammw.ResolvedAuthContext, error) {
	if claims == nil || claims.ActiveScopeID <= 0 {
		return nil, errors.NewCode(errors.Unauthorized, "active scope is required")
	}
	if r == nil || r.scopeAuthorizer == nil {
		return nil, errors.NewCode(errors.InvalidInput, "scope authorizer is required")
	}

	cacheKey := authContextCacheKey(claims.ActiveScopeID, claims.BindingVersion)
	if resolved, ok := r.loadCached(cacheKey); ok {
		cloned := resolved
		cloned.VisibleScopeIDs = append([]int64(nil), resolved.VisibleScopeIDs...)
		return &cloned, nil
	}

	scope, err := r.scopeAuthorizer.Scope(ctx, claims.ActiveScopeID)
	if err != nil {
		return nil, err
	}
	visibleScopeIDs, err := r.scopeAuthorizer.VisibleScopeIDs(ctx, claims.ActiveScopeID)
	if err != nil {
		return nil, err
	}
	resolved := iammw.ResolvedAuthContext{
		ActiveScopeID:   scope.ID,
		ActiveScopeKind: scope.Type,
		VisibleScopeIDs: visibleScopeIDs,
	}
	r.storeCached(cacheKey, resolved)
	cloned := resolved
	cloned.VisibleScopeIDs = append([]int64(nil), resolved.VisibleScopeIDs...)
	return &cloned, nil
}

func (r *AuthContextResolver) loadCached(key string) (iammw.ResolvedAuthContext, bool) {
	if r == nil || r.cacheTTL <= 0 || key == "" {
		return iammw.ResolvedAuthContext{}, false
	}
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if !ok {
		return iammw.ResolvedAuthContext{}, false
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	if !entry.expiresAt.IsZero() && now().After(entry.expiresAt) {
		return iammw.ResolvedAuthContext{}, false
	}
	return entry.resolved, true
}

func (r *AuthContextResolver) storeCached(key string, resolved iammw.ResolvedAuthContext) {
	if r == nil || r.cacheTTL <= 0 || key == "" {
		return
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	r.mu.Lock()
	r.cache[key] = authContextCacheEntry{resolved: resolved, expiresAt: now().Add(r.cacheTTL)}
	r.mu.Unlock()
}

// InvalidateBinding 在 binding 变动（新签发、撤销等）后主动失效缓存。
func (r *AuthContextResolver) InvalidateBinding(activeScopeID int64, bindingVersion string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.cache, authContextCacheKey(activeScopeID, bindingVersion))
	r.mu.Unlock()
}

func authContextCacheKey(activeScopeID int64, bindingVersion string) string {
	bindingVersion = strings.TrimSpace(bindingVersion)
	return fmt.Sprintf("%d|%s", activeScopeID, bindingVersion)
}

func InstallAuthContextResolver(resolver *AuthContextResolver) *AuthContextResolverInstaller {
	if resolver != nil {
		iammw.InstallAuthContextResolver(resolver)
	}
	return &AuthContextResolverInstaller{}
}
