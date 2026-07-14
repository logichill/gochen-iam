package service

import (
	"context"
	"testing"
	"time"

	iammw "gochen-iam/middleware"
	"gochen/errors"
)

type authSnapshotProviderStub struct {
	snapshot *ActiveScopeSession
	err      error
	calls    int
}

func (s *authSnapshotProviderStub) AuthSnapshot(context.Context, int64, int64) (*ActiveScopeSession, error) {
	s.calls++
	return s.snapshot, s.err
}

func TestAuthContextResolverRejectsStaleAuthorizationBeforeCacheHit(t *testing.T) {
	tests := []struct {
		name     string
		snapshot *ActiveScopeSession
	}{
		{
			name: "binding version changed",
			snapshot: &ActiveScopeSession{
				UserID:         7,
				ActiveScopeID:  11,
				BindingVersion: "binding-v2",
				Permissions:    []string{"orders.read", "orders.write"},
			},
		},
		{
			name: "permissions reduced",
			snapshot: &ActiveScopeSession{
				UserID:         7,
				ActiveScopeID:  11,
				BindingVersion: "binding-v1",
				Permissions:    []string{"orders.read"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &authSnapshotProviderStub{snapshot: tt.snapshot}
			resolver := cachedAuthContextResolver(provider)
			claims := &iammw.JWTClaims{
				UserID:         7,
				ActiveScopeID:  11,
				BindingVersion: "binding-v1",
				Permissions:    []string{"orders.read", "orders.write"},
			}

			resolved, err := resolver.ResolveAuthContext(context.Background(), claims)
			if !errors.Is(err, errors.Unauthorized) {
				t.Fatalf("expected stale token to be unauthorized, got resolved=%#v err=%v", resolved, err)
			}
			if provider.calls != 1 {
				t.Fatalf("expected current authorization lookup before cache hit, got %d calls", provider.calls)
			}
		})
	}
}

func TestAuthContextResolverRejectsDisabledUserBeforeCacheHit(t *testing.T) {
	provider := &authSnapshotProviderStub{
		err: errors.NewCode(errors.Forbidden, "user account is disabled"),
	}
	resolver := cachedAuthContextResolver(provider)
	claims := &iammw.JWTClaims{
		UserID:         7,
		ActiveScopeID:  11,
		BindingVersion: "binding-v1",
		Permissions:    []string{"orders.read"},
	}

	resolved, err := resolver.ResolveAuthContext(context.Background(), claims)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected disabled user to be forbidden, got resolved=%#v err=%v", resolved, err)
	}
	if provider.calls != 1 {
		t.Fatalf("expected current user status lookup before cache hit, got %d calls", provider.calls)
	}
}

func cachedAuthContextResolver(provider AuthSnapshotProvider) *AuthContextResolver {
	resolver := &AuthContextResolver{
		scopeAuthorizer:      &ScopeAuthorizer{},
		authSnapshotProvider: provider,
		cacheTTL:             time.Minute,
		now:                  time.Now,
		cache:                make(map[string]authContextCacheEntry),
	}
	resolver.cache[authContextCacheKey(11, "binding-v1")] = authContextCacheEntry{
		resolved: iammw.ResolvedAuthContext{
			ActiveScopeID:   11,
			ActiveScopeKind: string(iammw.ScopeTenant),
			VisibleScopeIDs: []int64{11},
		},
		expiresAt: time.Now().Add(time.Minute),
	}
	return resolver
}
