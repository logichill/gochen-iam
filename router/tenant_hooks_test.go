package router

import (
	"context"
	"gochen/auth/scoped"
	"strconv"
	"strings"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/errors"
)

type tenantHookRepoStub struct {
	tenants map[int64]*iamentity.Tenant
}

var _ svc.IResourceContextRepository[*iamentity.Tenant, int64] = (*tenantHookRepoStub)(nil)

func (s *tenantHookRepoStub) Create(context.Context, *iamentity.Tenant) error { return nil }

func (s *tenantHookRepoStub) Update(context.Context, *iamentity.Tenant) error { return nil }

func (s *tenantHookRepoStub) Delete(context.Context, int64) error { return nil }

func (s *tenantHookRepoStub) Get(_ context.Context, id int64) (*iamentity.Tenant, error) {
	tenant, ok := s.tenants[id]
	if !ok {
		return nil, errors.NewCode(errors.NotFound, "租户不存在")
	}
	cp := *tenant
	return &cp, nil
}

func (s *tenantHookRepoStub) ResolveResourceByID(_ context.Context, id int64) (scoped.Resource, error) {
	tenant, ok := s.tenants[id]
	if !ok {
		return scoped.Resource{}, errors.NewCode(errors.NotFound, "租户不存在")
	}
	return scoped.Resource{
		Kind: "iam.tenant",
		ID:   strconv.FormatInt(tenant.GetID(), 10),
	}, nil
}

func TestTenantCRUDHooks_DeleteRejectsActiveTenant(t *testing.T) {
	tenant := &iamentity.Tenant{
		Key:    "tenant-a",
		Status: svc.TenantStatusActive,
	}
	tenant.SetID(1)

	repo := &tenantHookRepoStub{
		tenants: map[int64]*iamentity.Tenant{1: tenant},
	}
	hooks := TenantHooksForTenant(repo, nil, &tenantDeleteGovernance{})

	err := hooks.BeforeDelete(context.Background(), 1)
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "请先停用租户再删除") {
		t.Fatalf("expected inactive-first message, got %v", err)
	}
}

func TestTenantCRUDHooks_DeleteRejectsOccupiedTenant(t *testing.T) {
	tenant := &iamentity.Tenant{
		Key:    "tenant-a",
		Status: svc.TenantStatusInactive,
	}
	tenant.SetID(2)

	repo := &tenantHookRepoStub{
		tenants: map[int64]*iamentity.Tenant{2: tenant},
	}
	hooks := TenantHooksForTenant(repo, nil, &tenantDeleteGovernance{
		countUsers: func(context.Context, string) (int64, error) { return 2, nil },
	})

	err := hooks.BeforeDelete(context.Background(), 2)
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "租户下仍有 2 个用户，不能删除。") {
		t.Fatalf("expected user-usage message, got %v", err)
	}
}

func TestTenantDeleteGovernance_StateReportsDeleteBlockReason(t *testing.T) {
	tenant := &iamentity.Tenant{
		Key:    "tenant-a",
		Status: svc.TenantStatusInactive,
	}

	governance := &tenantDeleteGovernance{
		countGroups: func(context.Context, string) (int64, error) { return 3, nil },
	}

	state, err := governance.State(context.Background(), tenant)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state.CanDelete {
		t.Fatalf("expected tenant delete to be blocked")
	}
	if state.DeleteBlockReason != "租户下仍有 3 个组织，不能删除。" {
		t.Fatalf("unexpected block reason: %q", state.DeleteBlockReason)
	}
}

func TestTenantCRUDHooks_DeleteRejectsRootScopeChildren(t *testing.T) {
	rootScopeID := int64(99)
	tenant := &iamentity.Tenant{
		Key:         "tenant-a",
		Status:      svc.TenantStatusInactive,
		RootScopeID: &rootScopeID,
	}
	tenant.SetID(3)

	repo := &tenantHookRepoStub{
		tenants: map[int64]*iamentity.Tenant{3: tenant},
	}
	hooks := TenantHooksForTenant(repo, nil, &tenantDeleteGovernance{
		countScopeChild: func(_ context.Context, scopeID int64) (int64, error) {
			if scopeID != rootScopeID {
				t.Fatalf("expected root scope id %d, got %d", rootScopeID, scopeID)
			}
			return 1, nil
		},
	})

	err := hooks.BeforeDelete(context.Background(), 3)
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "租户 root scope 下仍有 1 个子授权域，不能删除。") {
		t.Fatalf("expected child-scope message, got %v", err)
	}
}

func TestTenantCRUDHooks_DeleteRemovesRootScope(t *testing.T) {
	rootScopeID := int64(42)
	tenant := &iamentity.Tenant{
		Key:         "tenant-a",
		Status:      svc.TenantStatusInactive,
		RootScopeID: &rootScopeID,
	}
	tenant.SetID(4)

	repo := &tenantHookRepoStub{
		tenants: map[int64]*iamentity.Tenant{4: tenant},
	}

	var deletedScopeID int64
	rebuildCalls := 0
	hooks := TenantHooksForTenant(repo, nil, &tenantDeleteGovernance{
		countScopeChild: func(context.Context, int64) (int64, error) { return 0, nil },
		getScope: func(_ context.Context, scopeID int64) (*iamentity.Scope, error) {
			scope := &iamentity.Scope{}
			scope.SetID(scopeID)
			return scope, nil
		},
		deleteScope: func(_ context.Context, scope *iamentity.Scope) error {
			deletedScopeID = scope.ID
			return nil
		},
		rebuildScopeGraph: func(context.Context) error {
			rebuildCalls++
			return nil
		},
	})

	if err := hooks.BeforeDelete(context.Background(), 4); err != nil {
		t.Fatalf("expected delete hook to pass, got %v", err)
	}
	if deletedScopeID != rootScopeID {
		t.Fatalf("expected root scope %d to be deleted, got %d", rootScopeID, deletedScopeID)
	}
	if rebuildCalls != 1 {
		t.Fatalf("expected visibility rebuild once, got %d", rebuildCalls)
	}
}
