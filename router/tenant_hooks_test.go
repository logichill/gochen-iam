package router

import (
	"context"
	"strings"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	appcrud "gochen/app/crud"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/spec"
	"gochen/errors"
)

type tenantHookRepoStub struct {
	tenants map[int64]*iamentity.Tenant
}

var _ svc.IResourceContextRepository[*iamentity.Tenant, int64] = (*tenantHookRepoStub)(nil)

func (s *tenantHookRepoStub) Create(context.Context, *iamentity.Tenant, spec.Spec) error {
	return nil
}

func (s *tenantHookRepoStub) Update(context.Context, *iamentity.Tenant, spec.Spec) error {
	return nil
}

func (s *tenantHookRepoStub) Delete(context.Context, *iamentity.Tenant, spec.Spec) error {
	return nil
}

func (s *tenantHookRepoStub) Get(_ context.Context, id int64, _ spec.Spec) (*iamentity.Tenant, error) {
	tenant, ok := s.tenants[id]
	if !ok {
		return nil, errors.NewCode(errors.NotFound, "租户不存在")
	}
	cp := *tenant
	return &cp, nil
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

	err := hooks.For(appcrud.ActionDelete).Before(context.Background(), tenant)
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

	err := hooks.For(appcrud.ActionDelete).Before(context.Background(), tenant)
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
		getScope: func(_ context.Context, scopeID int64) (*iamentity.Scope, error) {
			scope := &iamentity.Scope{Key: "tenant:tenant-a", Type: iamentity.ScopeTypeTenant}
			scope.SetID(scopeID)
			return scope, nil
		},
		countScopeChild: func(_ context.Context, scopeID int64) (int64, error) {
			if scopeID != rootScopeID {
				t.Fatalf("expected root scope id %d, got %d", rootScopeID, scopeID)
			}
			return 1, nil
		},
	})

	err := hooks.For(appcrud.ActionDelete).Before(context.Background(), tenant)
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
			scope := &iamentity.Scope{Key: "tenant:tenant-a", Type: iamentity.ScopeTypeTenant}
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

	if err := hooks.For(appcrud.ActionDelete).Before(context.Background(), tenant); err != nil {
		t.Fatalf("expected delete hook to pass, got %v", err)
	}
	if deletedScopeID != rootScopeID {
		t.Fatalf("expected root scope %d to be deleted, got %d", rootScopeID, deletedScopeID)
	}
	if rebuildCalls != 1 {
		t.Fatalf("expected visibility rebuild once, got %d", rebuildCalls)
	}
}

func TestTenantDeleteGovernanceRejectsDriftAndRechecksBeforeWrite(t *testing.T) {
	rootID := int64(42)
	tenant := &iamentity.Tenant{Key: "tenant-a", Status: svc.TenantStatusInactive, RootScopeID: &rootID}
	tenant.SetID(4)
	for _, test := range []struct {
		name string
		root *iamentity.Scope
		err  error
	}{
		{name: "missing", err: errors.NewCode(errors.NotFound, "missing")},
		{name: "empty result"},
		{name: "foreign tenant", root: &iamentity.Scope{Key: "tenant:tenant-b", Type: iamentity.ScopeTypeTenant}},
		{name: "platform", root: &iamentity.Scope{Key: "platform", Type: iamentity.ScopeTypePlatform}},
		{name: "wrong type", root: &iamentity.Scope{Key: "tenant:tenant-a", Type: "org"}},
		{name: "wrong returned ID", root: &iamentity.Scope{Key: "tenant:tenant-a", Type: iamentity.ScopeTypeTenant}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.root != nil {
				test.root.SetID(rootID)
				if test.name == "wrong returned ID" {
					test.root.SetID(rootID + 1)
				}
			}
			children, deletes, rebuilds := 0, 0, 0
			g := &tenantDeleteGovernance{
				getScope:          func(context.Context, int64) (*iamentity.Scope, error) { return test.root, test.err },
				countScopeChild:   func(context.Context, int64) (int64, error) { children++; return 0, nil },
				deleteScope:       func(context.Context, *iamentity.Scope) error { deletes++; return nil },
				rebuildScopeGraph: func(context.Context) error { rebuilds++; return nil },
			}
			state, err := g.State(t.Context(), tenant)
			if err != nil || state.CanDelete || !strings.Contains(state.DeleteBlockReason, "先修复") {
				t.Fatalf("drift state=%+v error=%v", state, err)
			}
			if err := g.PrepareDelete(t.Context(), tenant); !errors.Is(err, errors.Validation) || !strings.Contains(err.Error(), "先修复") {
				t.Fatalf("drift delete=%v", err)
			}
			if children != 0 || deletes != 0 || rebuilds != 0 {
				t.Fatal("drifted root was used for child lookup or mutation")
			}
		})
	}
	reads, writes := 0, 0
	g := &tenantDeleteGovernance{
		getScope: func(context.Context, int64) (*iamentity.Scope, error) {
			reads++
			root := &iamentity.Scope{Key: "tenant:tenant-a", Type: iamentity.ScopeTypeTenant}
			root.SetID(rootID)
			if reads > 1 {
				root.Key = "tenant:tenant-b"
			}
			return root, nil
		},
		countScopeChild: func(context.Context, int64) (int64, error) { return 0, nil },
		deleteScope:     func(context.Context, *iamentity.Scope) error { writes++; return nil },
	}
	if err := g.PrepareDelete(t.Context(), tenant); !errors.Is(err, errors.Validation) || reads != 2 || writes != 0 {
		t.Fatalf("root changed after precheck: reads=%d writes=%d error=%v", reads, writes, err)
	}
}

type userHookRepoStub struct {
	users map[int64]*iamentity.User
}

func (s *userHookRepoStub) Create(context.Context, *iamentity.User, spec.Spec) error { return nil }
func (s *userHookRepoStub) Update(context.Context, *iamentity.User, spec.Spec) error { return nil }
func (s *userHookRepoStub) Delete(context.Context, *iamentity.User, spec.Spec) error { return nil }
func (s *userHookRepoStub) Get(_ context.Context, id int64, _ spec.Spec) (*iamentity.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, errors.NewCode(errors.NotFound, "用户不存在")
	}
	cp := &iamentity.User{
		TenantID:       u.TenantID,
		HomeTenantID:   u.HomeTenantID,
		HomeScopeID:    u.HomeScopeID,
		ManagedScopeID: u.ManagedScopeID,
		OwnerID:        u.OwnerID,
		Username:       u.Username,
		Email:          u.Email,
		Password:       u.Password,
		Status:         u.Status,
		Avatar:         u.Avatar,
		LastLoginAt:    u.LastLoginAt,
	}
	cp.SetID(u.GetID())
	return cp, nil
}

func TestTenantHooksForUser_PasswordHashed(t *testing.T) {
	ctx, err := contextx.WithTenantID(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("WithTenantID failed: %v", err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(10))
	if err != nil {
		t.Fatalf("WithDataScope failed: %v", err)
	}

	repo := &userHookRepoStub{users: make(map[int64]*iamentity.User)}
	hooks := TenantHooksForUser(repo)

	// 1. 创建用户时明文密码被哈希
	user := &iamentity.User{
		Username: "alice",
		Email:    "alice@example.com",
		Password: "password123",
	}
	if err := hooks.For(appcrud.ActionCreate).Before(ctx, user); err != nil {
		t.Fatalf("BeforeCreate failed: %v", err)
	}
	if user.Password == "password123" {
		t.Fatalf("expected password to be hashed, but was plain text")
	}
	if !isBcryptHash(user.Password) {
		t.Fatalf("expected valid bcrypt hash, got %s", user.Password)
	}

	// 2. 短密码被拒绝
	shortUser := &iamentity.User{
		Username: "bob",
		Email:    "bob@example.com",
		Password: "123",
	}
	if err := hooks.For(appcrud.ActionCreate).Before(ctx, shortUser); !errors.Is(err, errors.Validation) {
		t.Fatalf("expected validation error for short password, got: %v", err)
	}

	// 3. 更新时空密码继承已存在密码
	user.SetID(101)
	repo.users[101] = &iamentity.User{
		TenantID: user.TenantID,
		Password: user.Password,
	}
	updateUser := &iamentity.User{}
	updateUser.SetID(101)
	if err := hooks.For(appcrud.ActionUpdate).Before(ctx, updateUser); err != nil {
		t.Fatalf("BeforeUpdate with empty password failed: %v", err)
	}
	if updateUser.Password != user.Password {
		t.Fatalf("expected updated user to retain existing password hash")
	}

	// 4. 更新时传入新明文密码被哈希
	updateUserWithNewPass := &iamentity.User{Password: "newsecret456"}
	updateUserWithNewPass.SetID(101)
	if err := hooks.For(appcrud.ActionUpdate).Before(ctx, updateUserWithNewPass); err != nil {
		t.Fatalf("BeforeUpdate with new password failed: %v", err)
	}
	if updateUserWithNewPass.Password == "newsecret456" || !isBcryptHash(updateUserWithNewPass.Password) {
		t.Fatalf("expected new password to be hashed")
	}
}
