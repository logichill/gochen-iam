package service

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
)

type tenantBoundUserRepoStub struct {
	resource scoped.Resource
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

func (r *tenantBoundUserRepoStub) ResolveResourceByID(context.Context, int64) (scoped.Resource, error) {
	return r.resource, nil
}

func bindTenantScopedContext(t *testing.T, tenantID string, activeScopeID int64, scopeCode, scopeType string) context.Context {
	t.Helper()

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		ActiveScopeID: activeScopeID,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx, err = contextx.WithTenantID(ctx, tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, activeScopeID, scopeType)
	if activeScopeID > 0 {
		ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(activeScopeID))
		if err != nil {
			t.Fatalf("WithDataScope: %v", err)
		}
	}
	return ctx
}

func TestLoadTenantBoundResource_BindsResolvedTenantContext(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{OwnerID: tenantOwnerID("tenant-b")},
		entity:   &iamentity.User{TenantID: "tenant-b"},
	}
	repo.entity.SetID(7)

	ctx := bindTenantScopedContext(t, "tenant-a", 0, "", "")
	entity, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 7)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if entity.GetID() != 7 {
		t.Fatalf("expected entity id 7, got %d", entity.GetID())
	}
	if got := contextx.TenantID(repo.getCtx); got != "tenant-b" {
		t.Fatalf("expected repo get tenant-b, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-b" {
		t.Fatalf("expected returned ctx tenant-b, got %q", got)
	}
	principal, ok := auth.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on bound context")
	}
	if principal.SubjectID != 1 {
		t.Fatalf("expected subject 1, got %d", principal.SubjectID)
	}
}

func TestLoadTenantBoundResource_UsesStructuredTenantForPlatformOwnedResource(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{TenantID: "tenant-b", OwnerID: "platform"},
		entity:   &iamentity.User{TenantID: "tenant-b", OwnerID: "platform"},
	}
	repo.entity.SetID(8)

	entity, tenantCtx, err := LoadTenantBoundResource(context.Background(), repo, 8)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if entity.GetID() != 8 {
		t.Fatalf("expected entity id 8, got %d", entity.GetID())
	}
	if got := contextx.TenantID(repo.getCtx); got != "tenant-b" {
		t.Fatalf("expected repo get tenant-b, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-b" {
		t.Fatalf("expected returned ctx tenant-b, got %q", got)
	}
}

func TestLoadTenantBoundResource_WithoutTenantBoundaryKeepsOriginalContext(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{},
		entity:   &iamentity.User{},
	}
	repo.entity.SetID(11)

	ctx := bindTenantScopedContext(t, "tenant-a", 0, "", "")
	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 11)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if got := contextx.TenantID(repo.getCtx); got != "tenant-a" {
		t.Fatalf("expected original tenant tenant-a, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-a" {
		t.Fatalf("expected returned ctx tenant-a, got %q", got)
	}
}

func TestLoadTenantBoundResource_RebindsResolvedManagedScopeBoundary(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{
			OwnerID:        tenantOwnerID("tenant-a"),
			ManagedScopeID: 19,
		},
		entity: &iamentity.User{TenantID: "tenant-a"},
	}
	repo.entity.SetID(19)

	ctx := bindTenantScopedContext(t, "tenant-a", 7, "dept:ops", "department")
	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 19)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	scope, ok := scoped.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on repo context")
	}
	if len(scope.ScopeIDs) != 1 || scope.ScopeIDs[0] != 19 {
		t.Fatalf("expected rebound resource managed scope 19, got %+v", scope)
	}
	if scope.Kind != scoped.ScopeFiltered {
		t.Fatalf("expected managed scope mode, got %q", scope.Kind)
	}

	returnedScope, ok := scoped.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on returned ctx")
	}
	if len(returnedScope.ScopeIDs) != 1 || returnedScope.ScopeIDs[0] != 19 {
		t.Fatalf("expected returned ctx scope 19, got %+v", returnedScope)
	}
}

func TestLoadTenantBoundResource_PreservesScopeKindWhenManagedScopeUnchanged(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{
			OwnerID:        tenantOwnerID("tenant-a"),
			ManagedScopeID: 19,
		},
		entity: &iamentity.User{TenantID: "tenant-a"},
	}
	repo.entity.SetID(19)

	ctx := bindTenantScopedContext(t, "tenant-a", 19, "dept:ops", "department")
	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 19)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	if got := iamauth.ActiveScopeKindFromContext(repo.getCtx); got != "department" {
		t.Fatalf("expected repo ctx scope kind department, got %q", got)
	}
	if got := iamauth.ActiveScopeKindFromContext(tenantCtx); got != "department" {
		t.Fatalf("expected returned ctx scope kind department, got %q", got)
	}
}

func TestLoadTenantBoundResource_TenantOnlyBoundaryClearsPreviousManagedScope(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{OwnerID: tenantOwnerID("tenant-a")},
		entity:   &iamentity.User{TenantID: "tenant-a"},
	}
	repo.entity.SetID(21)

	ctx := bindTenantScopedContext(t, "tenant-a", 7, "dept:ops", "department")
	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 21)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	scope, ok := scoped.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on repo context")
	}
	if scope.Kind != scoped.ScopeGlobal || len(scope.ScopeIDs) != 0 {
		t.Fatalf("expected global scope after tenant-only rebound, got %+v", scope)
	}

	returnedScope, ok := scoped.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on returned ctx")
	}
	if returnedScope.Kind != scoped.ScopeGlobal {
		t.Fatalf("expected returned ctx global mode, got %q", returnedScope.Kind)
	}
}

func TestLoadTenantBoundResource_ClearsPlatformScopeWhenRebindingTenant(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		resource: scoped.Resource{OwnerID: tenantOwnerID("tenant-b")},
		entity:   &iamentity.User{TenantID: "tenant-b"},
	}
	repo.entity.SetID(23)

	ctx := bindTenantScopedContext(t, "tenant-a", 99, "/platform/", "platform")
	_, tenantCtx, err := LoadTenantBoundResource(ctx, repo, 23)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}

	principal, ok := auth.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on tenant context")
	}
	if principal.ActiveScopeID != 0 {
		t.Fatalf("expected platform scope id cleared, got %d", principal.ActiveScopeID)
	}
	if got := iamauth.ActiveScopeKindFromContext(tenantCtx); got != "" {
		t.Fatalf("expected active scope type cleared, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-b" {
		t.Fatalf("expected tenant-b, got %q", got)
	}

	scope, ok := scoped.DataScopeFromContext(repo.getCtx)
	if !ok {
		t.Fatalf("expected data scope on rebound context")
	}
	if scope.Kind != scoped.ScopeGlobal {
		t.Fatalf("expected global scope mode, got %q", scope.Kind)
	}
}

func TestBindTenantContext_PreservesSameTenantScopedContext(t *testing.T) {
	ctx := bindTenantScopedContext(t, "tenant-a", 7, "dept:ops", "department")

	tenantCtx, err := BindTenantContext(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("BindTenantContext: %v", err)
	}

	principal, ok := auth.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on tenant context")
	}
	if principal.ActiveScopeID != 7 {
		t.Fatalf("expected scoped principal preserved, got %+v", principal)
	}
	if got := iamauth.ActiveScopeKindFromContext(tenantCtx); got != "department" {
		t.Fatalf("expected active scope type preserved, got %q", got)
	}

	scope, ok := scoped.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on tenant context")
	}
	if scope.Kind != scoped.ScopeFiltered || len(scope.ScopeIDs) != 1 || scope.ScopeIDs[0] != 7 {
		t.Fatalf("expected scoped data scope preserved, got %+v", scope)
	}
}

func TestBindTenantContext_DefaultsToGlobalScopeWhenTenantIsUnscoped(t *testing.T) {
	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}

	tenantCtx, err := BindTenantContext(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("BindTenantContext: %v", err)
	}

	scope, ok := scoped.DataScopeFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected data scope on tenant context")
	}
	if scope.Kind != scoped.ScopeGlobal || len(scope.ScopeIDs) != 0 {
		t.Fatalf("expected global data scope, got %+v", scope)
	}
}
