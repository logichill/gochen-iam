package service

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	"gochen/authz"
	ctxx "gochen/contextx"
)

type tenantBoundUserRepoStub struct {
	resource authz.Resource
	entity   *iamentity.User
	getCtx   context.Context
}

func (r *tenantBoundUserRepoStub) Create(context.Context, *iamentity.User) error { return nil }
func (r *tenantBoundUserRepoStub) Update(context.Context, *iamentity.User) error { return nil }
func (r *tenantBoundUserRepoStub) Delete(context.Context, int64) error           { return nil }

func (r *tenantBoundUserRepoStub) Get(ctx context.Context, id int64) (*iamentity.User, error) {
	r.getCtx = ctx
	return r.entity, nil
}

func (r *tenantBoundUserRepoStub) ResolveResourceByID(context.Context, int64) (authz.Resource, error) {
	return r.resource, nil
}

func TestLoadTenantBoundResource_BindsResolvedTenantContext(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: authz.Resource{TenantID: "tenant-b"},
		entity:   &iamentity.User{TenantID: "tenant-b"},
	}
	repo.entity.SetID(7)

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID: 1,
		TenantID:  "tenant-a",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	entity, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 7)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if entity.GetID() != 7 {
		t.Fatalf("expected entity id 7, got %d", entity.GetID())
	}
	if got := ctxx.TenantID(repo.getCtx); got != "tenant-b" {
		t.Fatalf("expected repo get tenant-b, got %q", got)
	}
	principal, ok := authz.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on bound context")
	}
	if principal.TenantID != "tenant-b" {
		t.Fatalf("expected bound principal tenant-b, got %q", principal.TenantID)
	}
}

func TestLoadTenantBoundResource_WithoutTenantBoundaryKeepsOriginalContext(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: authz.Resource{},
		entity:   &iamentity.User{},
	}
	repo.entity.SetID(11)

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID: 1,
		TenantID:  "tenant-a",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 11)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if got := ctxx.TenantID(repo.getCtx); got != "tenant-a" {
		t.Fatalf("expected original tenant tenant-a, got %q", got)
	}
	if got := ctxx.TenantID(tenantCtx); got != "tenant-a" {
		t.Fatalf("expected returned ctx tenant tenant-a, got %q", got)
	}
}

func TestLoadTenantBoundResource_RebindsResolvedScopeBoundary(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: authz.Resource{
			TenantID:  "tenant-a",
			ScopeType: "department",
			ScopeCode: "dept:finance",
		},
		entity: &iamentity.User{TenantID: "tenant-a", ScopeType: "department", ScopeCode: "dept:finance"},
	}
	repo.entity.SetID(19)

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		ActiveScopeID:   7,
		ActiveScopeType: "department",
		ActiveScopeCode: "dept:ops",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{
		TenantID:  "tenant-a",
		ScopeType: "department",
		ScopeCode: "dept:ops",
		Mode:      authz.ScopeModeScoped,
	})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 19)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	scope, ok := authz.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on repo context")
	}
	if scope.TenantID != "tenant-a" || scope.ScopeType != "department" || scope.ScopeCode != "dept:finance" {
		t.Fatalf("expected rebound resource scope, got %+v", scope)
	}
	if scope.Mode != authz.ScopeModeScoped {
		t.Fatalf("expected scoped mode, got %q", scope.Mode)
	}

	returnedScope, ok := authz.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on returned ctx")
	}
	if returnedScope.ScopeCode != "dept:finance" {
		t.Fatalf("expected returned ctx scope dept:finance, got %+v", returnedScope)
	}
}

func TestLoadTenantBoundResource_TenantOnlyBoundaryClearsPreviousScopedFilter(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: authz.Resource{TenantID: "tenant-a"},
		entity:   &iamentity.User{TenantID: "tenant-a"},
	}
	repo.entity.SetID(21)

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		ActiveScopeID:   7,
		ActiveScopeType: "department",
		ActiveScopeCode: "dept:ops",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{
		TenantID:  "tenant-a",
		ScopeType: "department",
		ScopeCode: "dept:ops",
		Mode:      authz.ScopeModeScoped,
	})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 21)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	scope, ok := authz.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on repo context")
	}
	if scope.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %+v", scope)
	}
	if scope.Mode != authz.ScopeModeTenant {
		t.Fatalf("expected tenant mode, got %q", scope.Mode)
	}
	if scope.ScopeType != "" || scope.ScopeCode != "" || len(scope.ScopeCodes) != 0 {
		t.Fatalf("expected previous scoped filter cleared, got %+v", scope)
	}

	returnedScope, ok := authz.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on returned ctx")
	}
	if returnedScope.Mode != authz.ScopeModeTenant {
		t.Fatalf("expected returned ctx tenant mode, got %q", returnedScope.Mode)
	}
}

func TestLoadTenantBoundResource_ClearsPlatformScopeWhenRebindingTenant(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: authz.Resource{TenantID: "tenant-b"},
		entity:   &iamentity.User{TenantID: "tenant-b"},
	}
	repo.entity.SetID(23)

	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		ActiveScopeID:   99,
		ActiveScopeType: string(iammw.ScopePlatform),
		ActiveScopeCode: "platform",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{
		TenantID:  "tenant-a",
		ScopeType: string(iammw.ScopePlatform),
		ScopeCode: "platform",
		Mode:      authz.ScopeModeScoped,
	})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 23)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	principal, ok := authz.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on tenant context")
	}
	if principal.TenantID != "tenant-b" {
		t.Fatalf("expected tenant-b, got %q", principal.TenantID)
	}
	if principal.ActiveScopeID != 0 {
		t.Fatalf("expected platform scope id cleared, got %d", principal.ActiveScopeID)
	}
	if principal.ActiveScopeType != "" || principal.ActiveScopeCode != "" {
		t.Fatalf("expected platform scope cleared, got type=%q code=%q", principal.ActiveScopeType, principal.ActiveScopeCode)
	}

	scope, ok := authz.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on rebound context")
	}
	if scope.TenantID != "tenant-b" {
		t.Fatalf("expected scope tenant tenant-b, got %q", scope.TenantID)
	}
	if scope.Mode != authz.ScopeModeTenant {
		t.Fatalf("expected tenant scope mode, got %q", scope.Mode)
	}
	if scope.ScopeType != "" || scope.ScopeCode != "" || len(scope.ScopeCodes) != 0 {
		t.Fatalf("expected scoped boundary cleared, got %+v", scope)
	}
}

func TestBindTenantContext_PreservesNonPlatformScopedPrincipal(t *testing.T) {
	ctx, err := authz.WithPrincipal(context.Background(), authz.Principal{
		SubjectID:       1,
		TenantID:        "tenant-a",
		ActiveScopeID:   7,
		ActiveScopeType: "department",
		ActiveScopeCode: "dept:ops",
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = authz.WithDataScope(ctx, authz.DataScope{
		TenantID:  "tenant-a",
		ScopeType: "department",
		ScopeCode: "dept:ops",
		Mode:      authz.ScopeModeScoped,
	})
	if err != nil {
		t.Fatalf("WithDataScope: %v", err)
	}

	tenantCtx, err := BindTenantContext(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("BindTenantContext: %v", err)
	}

	principal, ok := authz.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on tenant context")
	}
	if principal.ActiveScopeID != 7 || principal.ActiveScopeType != "department" || principal.ActiveScopeCode != "dept:ops" {
		t.Fatalf("expected scoped principal preserved, got %+v", principal)
	}

	scope, ok := authz.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on tenant context")
	}
	if scope.Mode != authz.ScopeModeScoped || scope.ScopeType != "department" || scope.ScopeCode != "dept:ops" {
		t.Fatalf("expected scoped data scope preserved, got %+v", scope)
	}
}
