package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	scoperepo "gochen-iam/repo/scope"
	"gochen-iam/tenant"
	"gochen/domain/crud"
	"gochen/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

func TestAuthContextResolverVisibleScopesRespectTenantMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth_context_resolver.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	scopeRepo, err := scoperepo.NewScopeRepository(newScopeAuthorizerTestOrm(db))
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}

	platformID := int64(1)
	tenantRootID := int64(2)
	scopes := []*iamentity.Scope{
		{
			Entity: crud.Entity[int64]{ID: platformID},
			Key:    "platform",
			Name:   "Platform",
			Type:   iamentity.ScopeTypePlatform,
			Path:   "/platform/",
			Status: iamentity.ScopeStatusActive,
		},
		{
			Entity:   crud.Entity[int64]{ID: tenantRootID},
			Key:      "tenant:default",
			Name:     "Default",
			Type:     iamentity.ScopeTypeTenant,
			ParentID: &platformID,
			Path:     "/platform/tenant:default/",
			Depth:    1,
			Status:   iamentity.ScopeStatusActive,
		},
		{
			Entity:   crud.Entity[int64]{ID: 3},
			Key:      "tenant:sibling",
			Name:     "Sibling",
			Type:     iamentity.ScopeTypeTenant,
			ParentID: &platformID,
			Path:     "/platform/tenant:sibling/",
			Depth:    1,
			Status:   iamentity.ScopeStatusActive,
		},
		{
			Entity:   crud.Entity[int64]{ID: 4},
			Key:      "department",
			Name:     "Department",
			Type:     "department",
			ParentID: &tenantRootID,
			Path:     "/platform/tenant:default/department/",
			Depth:    2,
			Status:   iamentity.ScopeStatusActive,
		},
	}
	for _, scope := range scopes {
		if err := scopeRepo.Create(context.Background(), scope); err != nil {
			t.Fatalf("create scope %s: %v", scope.Key, err)
		}
	}
	if err := scopeRepo.RebuildVisibilityMap(context.Background()); err != nil {
		t.Fatalf("RebuildVisibilityMap: %v", err)
	}

	tests := []struct {
		name         string
		mode         tenant.Mode
		wantScopeIDs []int64
	}{
		{name: "single includes platform parent", mode: tenant.ModeSingle, wantScopeIDs: []int64{1, 2, 4}},
		{name: "tenant keeps scoped visibility", mode: tenant.ModeTenant, wantScopeIDs: []int64{2, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tenant.EnvTenantMode, string(tt.mode))
			provider := &authSnapshotProviderStub{snapshot: &ActiveScopeSession{
				UserID:         7,
				ActiveScopeID:  tenantRootID,
				BindingVersion: "binding-v1",
				Permissions:    []string{"api:user:list"},
			}}
			resolver := NewAuthContextResolver(NewScopeAuthorizer(scopeRepo, nil), provider)
			claims := &iammw.JWTClaims{
				UserID:         7,
				ActiveScopeID:  tenantRootID,
				BindingVersion: "binding-v1",
				Permissions:    []string{"api:user:list"},
			}

			resolved, err := resolver.ResolveAuthContext(context.Background(), claims)
			if err != nil {
				t.Fatalf("ResolveAuthContext: %v", err)
			}
			assertInt64Set(t, resolved.VisibleScopeIDs, tt.wantScopeIDs)
			if containsInt64(resolved.VisibleScopeIDs, 3) {
				t.Fatalf("sibling tenant scope must not be visible: %v", resolved.VisibleScopeIDs)
			}

			resolved.VisibleScopeIDs[0] = 999
			cached, err := resolver.ResolveAuthContext(context.Background(), claims)
			if err != nil {
				t.Fatalf("ResolveAuthContext cached: %v", err)
			}
			assertInt64Set(t, cached.VisibleScopeIDs, tt.wantScopeIDs)
		})
	}
}

func assertInt64Set(t *testing.T, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scope IDs = %v, want %v", got, want)
	}
	for _, id := range want {
		if !containsInt64(got, id) {
			t.Fatalf("scope IDs = %v, want %v", got, want)
		}
	}
}

func containsInt64(values []int64, target int64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
