package service

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/spec"
)

type tenantBoundUserRepoStub struct {
	entity *iamentity.User
	getCtx context.Context
}

func (r *tenantBoundUserRepoStub) Create(context.Context, *iamentity.User, spec.Spec) error {
	return nil
}
func (r *tenantBoundUserRepoStub) Update(context.Context, *iamentity.User, spec.Spec) error {
	return nil
}
func (r *tenantBoundUserRepoStub) Delete(context.Context, *iamentity.User, spec.Spec) error {
	return nil
}

func (r *tenantBoundUserRepoStub) Get(ctx context.Context, id int64, _ spec.Spec) (*iamentity.User, error) {
	r.getCtx = ctx
	return r.entity, nil
}

func bindTenantScopedContext(t *testing.T, tenantID string, activeScopeID int64, scopeCode, scopeType string) context.Context {
	t.Helper()

	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     "1",
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
		entity: &iamentity.User{TenantID: "tenant-b"},
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
	if got := contextx.TenantID(repo.getCtx); got != "tenant-a" {
		t.Fatalf("expected repo get to use the caller tenant-a, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-b" {
		t.Fatalf("expected returned ctx tenant-b, got %q", got)
	}
	principal, ok := auth.PrincipalFromContext(tenantCtx)
	if !ok {
		t.Fatalf("expected principal on bound context")
	}
	if principal.SubjectID != "1" {
		t.Fatalf("expected subject 1, got %s", principal.SubjectID)
	}
}

func TestLoadTenantBoundResource_UsesStructuredTenantForPlatformOwnedResource(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		entity: &iamentity.User{TenantID: "tenant-b", OwnerID: "platform"},
	}
	repo.entity.SetID(8)

	entity, tenantCtx, err := LoadTenantBoundResource(context.Background(), repo, 8)
	if err != nil {
		t.Fatalf("LoadTenantBoundResource: %v", err)
	}
	if entity.GetID() != 8 {
		t.Fatalf("expected entity id 8, got %d", entity.GetID())
	}
	if got := contextx.TenantID(repo.getCtx); got != "" {
		t.Fatalf("expected repo get to keep the unscoped caller context, got %q", got)
	}
	if got := contextx.TenantID(tenantCtx); got != "tenant-b" {
		t.Fatalf("expected returned ctx tenant-b, got %q", got)
	}
}

func TestLoadTenantBoundResource_WithoutTenantBoundaryKeepsOriginalContext(t *testing.T) {
	repo := &tenantBoundUserRepoStub{
		entity: &iamentity.User{},
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
