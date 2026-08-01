package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	iamtenant "gochen-iam/tenant"
	"gochen/errors"
)

// AuthContextResolverCacheTTL 控制 AuthContextResolver 的 binding 级缓存 TTL。
//
// 命中条件：相同 (active_scope_id, binding_version) 组合；未命中时回源
// ScopeAuthorizer 的 scope/visibility 查询。设置为 0 表示禁用缓存。
const AuthContextResolverCacheTTL = 30 * time.Second

// AuthContextResolver 将 access token claims 还原为运行时可消费的 scope 边界。
type AuthContextResolver struct {
	scopeAuthorizer      *ScopeAuthorizer
	authSnapshotProvider AuthSnapshotProvider
	cacheTTL             time.Duration
	now                  func() time.Time

	mu    sync.RWMutex
	cache map[string]authContextCacheEntry
}

type authContextCacheEntry struct {
	resolved  iammw.ResolvedAuthContext
	expiresAt time.Time
}

// AuthSnapshotProvider 返回用户在目标授权域下的当前授权快照。
type AuthSnapshotProvider interface {
	AuthSnapshot(ctx context.Context, userID, activeScopeID int64) (*ActiveScopeSession, error)
}

// AuthContextResolverInstaller 仅用于把 resolver 注册进 middleware 运行时。
type AuthContextResolverInstaller struct{}

func NewAuthContextResolver(scopeAuthorizer *ScopeAuthorizer, authSnapshotProvider AuthSnapshotProvider) *AuthContextResolver {
	resolver := &AuthContextResolver{
		scopeAuthorizer:      scopeAuthorizer,
		authSnapshotProvider: authSnapshotProvider,
		cacheTTL:             AuthContextResolverCacheTTL,
		now:                  time.Now,
		cache:                make(map[string]authContextCacheEntry),
	}
	iammw.InstallAuthContextResolver(resolver)
	return resolver
}

func (r *AuthContextResolver) ResolveAuthContext(ctx context.Context, claims *iammw.JWTClaims) (*iammw.ResolvedAuthContext, error) {
	if claims == nil || claims.UserID <= 0 || claims.ActiveScopeID <= 0 {
		return nil, errors.NewCode(errors.Unauthorized, "active scope is required")
	}
	if r == nil || r.scopeAuthorizer == nil || r.authSnapshotProvider == nil {
		return nil, errors.NewCode(errors.InvalidInput, "auth context resolver dependencies are required")
	}

	snapshot, err := r.authSnapshotProvider.AuthSnapshot(ctx, claims.UserID, claims.ActiveScopeID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || snapshot.UserID != claims.UserID || snapshot.ActiveScopeID != claims.ActiveScopeID {
		return nil, errors.NewCode(errors.Unauthorized, "access token authorization is invalid")
	}
	if strings.TrimSpace(snapshot.BindingVersion) != strings.TrimSpace(claims.BindingVersion) ||
		!samePermissionSet(snapshot.Permissions, claims.Permissions) {
		return nil, errors.NewCode(errors.Unauthorized, "access token authorization is stale")
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
	if iamtenant.Current().IsSingle() && scope.Type == iamentity.ScopeTypeTenant {
		visibleScopeIDs, err = r.includeSingleTenantPlatformScope(ctx, scope, visibleScopeIDs)
		if err != nil {
			return nil, err
		}
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

func (r *AuthContextResolver) includeSingleTenantPlatformScope(
	ctx context.Context,
	scope *iamentity.Scope,
	visibleScopeIDs []int64,
) ([]int64, error) {
	if scope == nil || scope.ParentID == nil || *scope.ParentID <= 0 {
		return nil, errors.NewCode(errors.Internal, "single tenant root scope parent is missing")
	}
	parent, err := r.scopeAuthorizer.Scope(ctx, *scope.ParentID)
	if err != nil {
		return nil, errors.Wrap(err, errors.Internal, "resolve single tenant root scope parent failed")
	}
	if parent == nil || parent.Type != iamentity.ScopeTypePlatform {
		return nil, errors.NewCode(errors.Internal, "single tenant root scope parent must be platform")
	}
	for _, scopeID := range visibleScopeIDs {
		if scopeID == parent.ID {
			return visibleScopeIDs, nil
		}
	}
	return append(visibleScopeIDs, parent.ID), nil
}

func samePermissionSet(left, right []string) bool {
	leftSet := make(map[string]struct{}, len(left))
	for _, permission := range left {
		if permission = strings.TrimSpace(permission); permission != "" {
			leftSet[permission] = struct{}{}
		}
	}
	rightSet := make(map[string]struct{}, len(right))
	for _, permission := range right {
		if permission = strings.TrimSpace(permission); permission != "" {
			rightSet[permission] = struct{}{}
		}
	}
	if len(leftSet) != len(rightSet) {
		return false
	}
	for permission := range leftSet {
		if _, ok := rightSet[permission]; !ok {
			return false
		}
	}
	return true
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
