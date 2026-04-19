package router

import (
	"context"
	"testing"

	"gochen-iam/access"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	rolesvc "gochen-iam/service/role"
	"gochen/errors"
)

type roleHookRepoStub struct {
	roles        map[int64]*iamentity.Role
	groupUsage   map[int64]int64
	lastResolved int64
}

var _ svc.IResourceContextRepository[*iamentity.Role, int64] = (*roleHookRepoStub)(nil)

func (s *roleHookRepoStub) Create(context.Context, *iamentity.Role) error { return nil }

func (s *roleHookRepoStub) Update(_ context.Context, role *iamentity.Role) error {
	cp := cloneRole(role)
	s.roles[role.GetID()] = cp
	return nil
}

func (s *roleHookRepoStub) Delete(context.Context, int64) error { return nil }

func (s *roleHookRepoStub) Get(_ context.Context, id int64) (*iamentity.Role, error) {
	role, ok := s.roles[id]
	if !ok {
		return nil, errors.NewCode(errors.NotFound, "角色不存在")
	}
	return cloneRole(role), nil
}

func (s *roleHookRepoStub) ResolveResourceByID(_ context.Context, id int64) (access.ResourceBoundary, error) {
	role, ok := s.roles[id]
	if !ok {
		return access.ResourceBoundary{}, errors.NewCode(errors.NotFound, "角色不存在")
	}
	s.lastResolved = id
	return access.ResourceBoundary{
		Kind:           "iam.role",
		ID:             "role",
		OwnerID:        "tenant:" + role.GetTenantID(),
		ManagedScopeID: role.NamespaceScopeID,
	}, nil
}

func (s *roleHookRepoStub) FindByName(ctx context.Context, name string) (*iamentity.Role, error) {
	tenantID, _ := svc.TenantIDFromContext(ctx)
	for _, role := range s.roles {
		if role.Name != name {
			continue
		}
		if tenantID != "" && role.GetTenantID() != tenantID {
			continue
		}
		return cloneRole(role), nil
	}
	return nil, errors.NewCode(errors.NotFound, "角色不存在")
}

func (s *roleHookRepoStub) CountGroupsByRoleID(_ context.Context, roleID int64) (int64, error) {
	return s.groupUsage[roleID], nil
}

type roleUsageCounterStub struct {
	userUsage map[int64]int64
}

func (s *roleUsageCounterStub) CountByRoleID(_ context.Context, roleID int64) (int64, error) {
	return s.userUsage[roleID], nil
}

func TestRoleCRUDHooks_CreateRejectsBuiltinWildcardPermissions(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	repo := &roleHookRepoStub{
		roles:      map[int64]*iamentity.Role{},
		groupUsage: map[int64]int64{},
	}
	governance := rolesvc.NewGovernance(repo, &roleUsageCounterStub{userUsage: map[int64]int64{}}, nil)
	hooks := newScopeBackedRoleCRUDHooks(repo, nil, governance)

	role := &iamentity.Role{
		Name:        "自定义管理员",
		Description: "test",
		Permissions: iamentity.PermissionArray{"api:*:*"},
	}

	err := hooks.BeforeCreate(tenantCtx(t, "tenant-a"), role)
	if err == nil {
		t.Fatalf("expected builtin wildcard permission to be rejected")
	}
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestRoleCRUDHooks_CreateAppliesServiceDefaults(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	repo := &roleHookRepoStub{
		roles:      map[int64]*iamentity.Role{},
		groupUsage: map[int64]int64{},
	}
	governance := rolesvc.NewGovernance(repo, &roleUsageCounterStub{userUsage: map[int64]int64{}}, nil)
	hooks := newScopeBackedRoleCRUDHooks(repo, nil, governance)

	role := &iamentity.Role{
		Code:        "mutated",
		Name:        "租户管理员",
		Permissions: iamentity.PermissionArray{"api:role:read"},
		IsSystem:    true,
		Status:      "inactive",
	}

	if err := hooks.BeforeCreate(tenantCtx(t, "tenant-a"), role); err != nil {
		t.Fatalf("BeforeCreate: %v", err)
	}
	if role.GetTenantID() != "tenant-a" {
		t.Fatalf("expected tenant_id tenant-a, got %q", role.GetTenantID())
	}
	if role.GetOwnerID() != svc.TenantOwnerID("tenant-a") {
		t.Fatalf("expected owner_id to be normalized, got %q", role.GetOwnerID())
	}
	if role.NamespaceScopeID != 1 {
		t.Fatalf("expected namespace scope 1, got %d", role.NamespaceScopeID)
	}
	if role.Code != role.Name {
		t.Fatalf("expected code to follow name, got %q", role.Code)
	}
	if role.IsSystem {
		t.Fatalf("expected create hook to force non-system role")
	}
	if role.Status != svc.RoleStatusActive {
		t.Fatalf("expected status active, got %q", role.Status)
	}
}

func TestRoleCRUDHooks_UpdateRejectsSystemRoleMutation(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	role := &iamentity.Role{
		TenantID:         "tenant-a",
		OwnerID:          svc.TenantOwnerID("tenant-a"),
		NamespaceScopeID: 1,
		Code:             "system-admin",
		Name:             "系统管理员",
		Permissions:      iamentity.PermissionArray{"api:role:read"},
		IsSystem:         true,
		Status:           svc.RoleStatusActive,
	}
	role.SetID(1)

	repo := &roleHookRepoStub{
		roles:      map[int64]*iamentity.Role{1: role},
		groupUsage: map[int64]int64{},
	}
	governance := rolesvc.NewGovernance(repo, &roleUsageCounterStub{userUsage: map[int64]int64{}}, nil)
	hooks := newScopeBackedRoleCRUDHooks(repo, nil, governance)

	updating := cloneRole(role)
	updating.Name = "试图修改"
	updating.Code = "hacked"
	updating.IsSystem = false

	err := hooks.BeforeUpdate(tenantCtx(t, "tenant-a"), updating)
	if err == nil {
		t.Fatalf("expected system role mutation to be rejected")
	}
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestRoleCRUDHooks_UpdateRestoresImmutableFields(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	role := &iamentity.Role{
		TenantID:         "tenant-a",
		OwnerID:          svc.TenantOwnerID("tenant-a"),
		NamespaceScopeID: 1,
		Code:             "auditor",
		Name:             "审计员",
		Permissions:      iamentity.PermissionArray{"api:role:read"},
		IsSystem:         false,
		Status:           svc.RoleStatusActive,
	}
	role.SetID(2)

	repo := &roleHookRepoStub{
		roles:      map[int64]*iamentity.Role{2: role},
		groupUsage: map[int64]int64{},
	}
	governance := rolesvc.NewGovernance(repo, &roleUsageCounterStub{userUsage: map[int64]int64{}}, nil)
	hooks := newScopeBackedRoleCRUDHooks(repo, nil, governance)

	updating := cloneRole(role)
	updating.Name = "审计员-新"
	updating.Code = "mutated"
	updating.Status = "inactive"
	updating.IsSystem = true
	updating.Permissions = iamentity.PermissionArray{"api:user:read"}

	if err := hooks.BeforeUpdate(tenantCtx(t, "tenant-a"), updating); err != nil {
		t.Fatalf("BeforeUpdate: %v", err)
	}
	if updating.Code != "auditor" {
		t.Fatalf("expected code to stay immutable, got %q", updating.Code)
	}
	if updating.Status != svc.RoleStatusActive {
		t.Fatalf("expected status to stay active, got %q", updating.Status)
	}
	if updating.IsSystem {
		t.Fatalf("expected is_system to stay false")
	}
	if updating.GetTenantID() != "tenant-a" {
		t.Fatalf("expected tenant_id tenant-a, got %q", updating.GetTenantID())
	}
}

func TestRoleCRUDHooks_DeleteRejectsInUseAndCrossTenantRole(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	role := &iamentity.Role{
		TenantID:         "tenant-a",
		OwnerID:          svc.TenantOwnerID("tenant-a"),
		NamespaceScopeID: 1,
		Code:             "operator",
		Name:             "运营",
		Permissions:      iamentity.PermissionArray{"api:role:read"},
		Status:           svc.RoleStatusActive,
	}
	role.SetID(3)

	repo := &roleHookRepoStub{
		roles:      map[int64]*iamentity.Role{3: role},
		groupUsage: map[int64]int64{3: 0},
	}
	governance := rolesvc.NewGovernance(repo, &roleUsageCounterStub{userUsage: map[int64]int64{3: 1}}, nil)
	hooks := newScopeBackedRoleCRUDHooks(repo, nil, governance)

	if err := hooks.BeforeDelete(tenantCtx(t, "tenant-a"), 3); !errors.Is(err, errors.Validation) {
		t.Fatalf("expected in-use role delete to fail with validation error, got %v", err)
	}
	if err := hooks.BeforeDelete(tenantCtx(t, "tenant-b"), 3); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected cross-tenant delete to fail with forbidden error, got %v", err)
	}
}

func cloneRole(role *iamentity.Role) *iamentity.Role {
	if role == nil {
		return nil
	}
	cp := *role
	if role.Permissions != nil {
		cp.Permissions = append(iamentity.PermissionArray{}, role.Permissions...)
	}
	return &cp
}
