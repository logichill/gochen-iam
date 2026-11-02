package user

import (
	"context"
	"database/sql"
	"fmt"
	"gochen/domain/meta"

	coredialect "gochen/db/dialect"
	"gochen/testkit"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-runtime/db/dialect"

	auth "gochen-runtime/host/authz"

	appcrud "gochen/app/crud"

	goauth "gochen/auth"
	"gochen/contextx"
	"gochen/db"
	"gochen/db/orm"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserRepoNativeWritesRejectEmptySpec(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			engine := &fakeOrm{baseModel: &capturingModel{}, sessionModel: &capturingModel{}}
			repository, err := NewUserRepository(engine, testkit.NewInt64Sequence(1))
			if err != nil {
				t.Fatal(err)
			}
			ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
			entity := &iamentity.User{TenantID: "tenant-a"}
			entity.SetID(7)
			if operation == "create" {
				err = repository.Create(ctx, entity, spec.Spec{})
			} else {
				err = repository.Update(ctx, entity, spec.Spec{})
			}
			if !errors.Is(err, errors.Forbidden) {
				t.Fatalf("expected empty spec rejection, got %v", err)
			}
			if engine.baseModel.createCalls != 0 || engine.baseModel.savedEntity != nil {
				t.Fatal("empty spec reached persistence")
			}
		})
	}
}

type scopeAuthorizerStub struct {
	spec spec.Spec
}

func (s scopeAuthorizerStub) Authorize(context.Context, goauth.Request) (goauth.Decision, error) {
	return goauth.Decision{Allowed: true, Spec: s.spec}, nil
}

func (s scopeAuthorizerStub) Vocabulary() goauth.Vocabulary {
	return goauth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}

func TestUserApplicationRejectsHookScopeWidening(t *testing.T) {
	engine := &fakeOrm{baseModel: &capturingModel{}, sessionModel: &capturingModel{}}
	repository, err := NewUserRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	beforeCalled := false
	base, err := appcrud.NewApplication[*iamentity.User, int64](repository, appcrud.Options[*iamentity.User, int64]{
		Resource:   "user",
		Authorizer: scopeAuthorizerStub{spec: spec.Eq(meta.ByDimension("scope"), 1)},
		Hooks: appcrud.Hooks[*iamentity.User]{
			appcrud.ActionCreate: {
				Before: func(_ context.Context, user *iamentity.User) error {
					beforeCalled = true
					user.ManagedScopeID = 99
					return nil
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{
		TenantID:       "tenant-a",
		HomeTenantID:   "tenant-a",
		HomeScopeID:    1,
		ManagedScopeID: 1,
		OwnerID:        tenantOwnerID("tenant-a"),
		Username:       "hookuser",
		Email:          "hook@example.com",
		Password:       "password123",
		Status:         "active",
	}
	user.SetID(7)
	err = base.Create(withTenantPrincipal(t, context.Background(), "tenant-a"), user)
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected hook scope widening to be rejected, got %v", err)
	}
	if !beforeCalled {
		t.Fatal("expected create hook to run")
	}
	if engine.baseModel.createCalls != 0 || engine.sessionModel.createCalls != 0 {
		t.Fatalf("out-of-scope hook write reached persistence: base=%d tx=%d", engine.baseModel.createCalls, engine.sessionModel.createCalls)
	}
}

type capturingAssociation struct {
	appendCalls int
	deleteCalls int
}

func (a *capturingAssociation) Name() string                          { return "" }
func (a *capturingAssociation) Owner() any                            { return nil }
func (a *capturingAssociation) Append(context.Context, ...any) error  { a.appendCalls++; return nil }
func (a *capturingAssociation) Replace(context.Context, ...any) error { return nil }
func (a *capturingAssociation) Delete(context.Context, ...any) error  { a.deleteCalls++; return nil }
func (a *capturingAssociation) Clear(context.Context) error           { return nil }

type capturingModel struct {
	meta *orm.ModelMeta

	firstCalls       int
	findCalls        int
	createCalls      int
	createdEntity    any
	associationCalls int
	lastFirstOpts    orm.QueryOptions
	lastOpts         orm.QueryOptions
	lastCountOpts    orm.QueryOptions

	lastAssociation  *capturingAssociation
	savedEntity      any
	lastUpdateOpts   orm.QueryOptions
	lastUpdateValues map[string]any
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) Dialect() coredialect.IDialect  { return dialect.New("sqlite") }
func (m *capturingModel) First(_ context.Context, _ any, opts ...orm.QueryOption) error {
	m.firstCalls++
	m.lastFirstOpts = orm.CollectQueryOptions(opts...)
	return nil
}
func (m *capturingModel) Find(_ context.Context, _ any, opts ...orm.QueryOption) error {
	m.findCalls++
	m.lastOpts = orm.CollectQueryOptions(opts...)
	return nil
}
func (m *capturingModel) Count(_ context.Context, opts ...orm.QueryOption) (int64, error) {
	m.lastCountOpts = orm.CollectQueryOptions(opts...)
	return 0, nil
}
func (m *capturingModel) Create(_ context.Context, entities ...any) error {
	m.createCalls++
	if len(entities) > 0 {
		m.createdEntity = entities[0]
	}
	return nil
}
func (m *capturingModel) Save(_ context.Context, entity any, opts ...orm.QueryOption) error {
	m.savedEntity = entity
	m.lastOpts = orm.CollectQueryOptions(opts...)
	return nil
}

type affectedResult int64

func (r affectedResult) LastInsertId() (int64, error) { return 0, nil }
func (r affectedResult) RowsAffected() (int64, error) { return int64(r), nil }
func (m *capturingModel) SaveWithResult(ctx context.Context, entity any, opts ...orm.QueryOption) (sql.Result, error) {
	return affectedResult(1), m.Save(ctx, entity, opts...)
}
func (m *capturingModel) UpdateValuesWithResult(ctx context.Context, values map[string]any, opts ...orm.QueryOption) (sql.Result, error) {
	return affectedResult(1), m.UpdateValues(ctx, values, opts...)
}
func (m *capturingModel) DeleteWithResult(ctx context.Context, opts ...orm.QueryOption) (sql.Result, error) {
	return affectedResult(1), m.Delete(ctx, opts...)
}
func (m *capturingModel) UpdateValues(_ context.Context, values map[string]any, opts ...orm.QueryOption) error {
	m.lastUpdateOpts = orm.CollectQueryOptions(opts...)
	m.lastUpdateValues = values
	return nil
}
func (m *capturingModel) Delete(context.Context, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Association(any, string) orm.IAssociation {
	m.associationCalls++
	a := &capturingAssociation{}
	m.lastAssociation = a
	return a
}

type fakeOrm struct {
	baseModel    *capturingModel
	sessionModel *capturingModel
}

func (o *fakeOrm) DatasourceID() string { return fmt.Sprintf("iam-user-test:%p", o) }

func (o *fakeOrm) Capabilities() orm.Capabilities           { return nil }
func (o *fakeOrm) WithContext(ctx context.Context) orm.IOrm { return o }
func (o *fakeOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	o.baseModel.meta = meta
	return o.baseModel, nil
}
func (o *fakeOrm) Begin(context.Context) (orm.IOrmSession, error) {
	return &fakeSession{parent: o}, nil
}
func (o *fakeOrm) BeginTx(context.Context, *sql.TxOptions) (orm.IOrmSession, error) {
	return &fakeSession{parent: o}, nil
}
func (o *fakeOrm) Database() db.IDatabase { return nil }
func (o *fakeOrm) Raw() any               { return nil }

type fakeSession struct {
	parent *fakeOrm
}

func (s *fakeSession) DatasourceID() string { return s.parent.DatasourceID() }

func (s *fakeSession) Capabilities() orm.Capabilities           { return nil }
func (s *fakeSession) WithContext(ctx context.Context) orm.IOrm { return s }
func (s *fakeSession) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	s.parent.sessionModel.meta = meta
	return s.parent.sessionModel, nil
}
func (s *fakeSession) Begin(ctx context.Context) (orm.IOrmSession, error) { return s, nil }
func (s *fakeSession) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	return s, nil
}
func (s *fakeSession) Database() db.IDatabase { return nil }
func (s *fakeSession) Raw() any               { return nil }
func (s *fakeSession) Commit() error          { return nil }
func (s *fakeSession) Rollback() error        { return nil }

func withTenantPrincipal(t *testing.T, ctx context.Context, tenantID string) context.Context {
	t.Helper()
	derived, err := auth.WithPrincipal(ctx, auth.Principal{SubjectID: "1", ActiveScopeID: 1})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	derived, err = contextx.WithTenantID(derived, tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	return derived
}

func TestUserRepo_Get_UsesTxSessionModel(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	txCtx = withTenantPrincipal(t, txCtx, "tenant-a")
	if _, err := r.Get(txCtx, 1, spec.All()); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if o.baseModel.firstCalls != 0 {
		t.Fatalf("expected base model not used, got firstCalls=%d", o.baseModel.firstCalls)
	}
	if o.sessionModel.firstCalls != 1 {
		t.Fatalf("expected session model used once, got firstCalls=%d", o.sessionModel.firstCalls)
	}
}

func TestUserRepo_AssignRole_UsesTxSessionBindingModel(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	// 模拟由应用事务生命周期托管的外层事务（提交后回调由外层负责传播）。
	txCtx, err = contextx.WithTxLifecycle(txCtx, false)
	if err != nil {
		t.Fatalf("WithTxLifecycle: %v", err)
	}
	txCtx = withTenantPrincipal(t, txCtx, "tenant-a")
	if err := r.AssignRole(txCtx, 1, 2, spec.All()); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	if o.baseModel.createCalls != 0 {
		t.Fatalf("expected base model create not used, got createCalls=%d", o.baseModel.createCalls)
	}
	if o.sessionModel.firstCalls != 3 {
		t.Fatalf("expected session model first used for user+role lookups and binding owner check, got firstCalls=%d", o.sessionModel.firstCalls)
	}
	if o.sessionModel.createCalls != 1 {
		t.Fatalf("expected session binding model create used once, got createCalls=%d", o.sessionModel.createCalls)
	}
}

func TestUserRepo_Get_FiltersByTenantFromPrincipal(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.Get(ctx, 7, spec.All()); err != nil {
		t.Fatalf("Get: %v", err)
	}

	where := o.baseModel.lastFirstOpts.Where
	requireCondition(t, where, `"tenant_id" = ?`, "tenant-a")
	requireCondition(t, where, `"id" = ?`, int64(7))
	requireCondition(t, where, `"deleted_at" IS NULL`)
}

func TestUserRepo_Update_StripsAssociationsBeforeSave(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	user := &iamentity.User{
		TenantID:       "tenant-a",
		HomeTenantID:   "tenant-a",
		HomeScopeID:    1,
		ManagedScopeID: 1,
		OwnerID:        "tenant:tenant-a",
		Username:       "admin",
		Email:          "admin@example.com",
		Password:       "hashed",
		Groups:         []iamentity.Group{{}},
		Roles:          []iamentity.Role{{}},
	}
	user.SetID(7)

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if err := r.Update(ctx, user, spec.All()); err != nil {
		t.Fatalf("Update: %v", err)
	}

	values := o.baseModel.lastUpdateValues
	if values == nil {
		t.Fatal("expected update values to be written")
	}
	if _, ok := values["groups"]; ok {
		t.Fatalf("expected associations stripped before save, got %#v", values)
	}
	if _, ok := values["roles"]; ok {
		t.Fatalf("expected associations stripped before save, got %#v", values)
	}
	requireCondition(t, o.baseModel.lastUpdateOpts.Where, `"version" = ?`, uint64(0))
	if user.GetVersion() != 1 {
		t.Fatalf("expected returned entity version 1, got %d", user.GetVersion())
	}
}

func requireCondition(t *testing.T, conditions []orm.Condition, expr string, wantArgs ...any) {
	t.Helper()
	for _, condition := range conditions {
		if condition.Expr != expr {
			continue
		}
		if len(condition.Args) != len(wantArgs) {
			t.Fatalf("unexpected arg count for %q: %#v", expr, condition.Args)
		}
		for i := range wantArgs {
			if condition.Args[i] != wantArgs[i] {
				t.Fatalf("unexpected arg %d for %q: %#v", i, expr, condition.Args)
			}
		}
		return
	}
	t.Fatalf("condition %q not found in %#v", expr, conditions)
}

func TestUserRepo_UpdateLastLogin_ScopedToTenant(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	// 1. Without tenant context, should fail
	if err := r.UpdateLastLogin(context.Background(), 100); err == nil {
		t.Fatal("expected error without tenant context, got nil")
	}

	// 2. With tenant context, should include tenant_id in where condition
	ctx := withTenantPrincipal(t, context.Background(), "tenant-xyz")
	if err := r.UpdateLastLogin(ctx, 100); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}

	where := o.baseModel.lastUpdateOpts.Where
	requireCondition(t, where, "id = ? AND tenant_id = ? AND deleted_at IS NULL", int64(100), "tenant-xyz")
}

func TestUserRepo_Create_RequiresTenant(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	user := &iamentity.User{
		Username: "alice",
	}

	// 1. 无租户上下文，必须拒绝创建并返回错误 (F16)
	if err := r.Create(context.Background(), user, spec.All()); err == nil {
		t.Fatal("expected error creating user without tenant in context, got nil")
	}

	// 2. 跨租户创建，必须返回 Forbidden
	ctx := withTenantPrincipal(t, context.Background(), "tenant-alpha")
	crossTenantUser := &iamentity.User{
		Username: "bob",
		TenantID: "tenant-beta",
	}
	if err := r.Create(ctx, crossTenantUser, spec.All()); err == nil {
		t.Fatal("expected forbidden error on cross-tenant create, got nil")
	}

	// 3. 正常同租户创建成功
	if err := r.Create(ctx, user, spec.All()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if user.TenantID != "tenant-alpha" {
		t.Fatalf("expected tenant_id 'tenant-alpha', got %q", user.TenantID)
	}
}

func TestUserRepo_RoleByID_ScopedToTenant(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	// 1. 无租户上下文，必须失败
	if _, err := r.roleByID(context.Background(), 10); err == nil {
		t.Fatal("expected error without tenant context, got nil")
	}

	// 2. 有租户上下文，查询条件必须包含 tenant_id (F15)
	ctx := withTenantPrincipal(t, context.Background(), "tenant-alpha")
	_, _ = r.roleByID(ctx, 10)

	where := o.baseModel.lastFirstOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-alpha")
	requireCondition(t, where, "id = ?", int64(10))
}

func TestUserRepo_CountByScopeID_ScopedToTenant(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}

	// 1. 无租户上下文（平台模式），不限定 tenant_id
	if _, err := r.CountByHomeScopeID(context.Background(), 10); err != nil {
		t.Fatalf("CountByHomeScopeID: %v", err)
	}
	where := o.baseModel.lastCountOpts.Where
	requireCondition(t, where, "home_scope_id = ? AND deleted_at IS NULL", int64(10))

	// 2. 传入租户上下文，CountByHomeScopeID 必须带 tenant_id 隔离过滤 (F50)
	ctx := withTenantPrincipal(t, context.Background(), "tenant-alpha")
	if _, err := r.CountByHomeScopeID(ctx, 10); err != nil {
		t.Fatalf("CountByHomeScopeID: %v", err)
	}
	where = o.baseModel.lastCountOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-alpha")
	requireCondition(t, where, "home_scope_id = ? AND deleted_at IS NULL", int64(10))

	// 3. CountByManagedScopeID 必须带 tenant_id 隔离过滤 (F50)
	if _, err := r.CountByManagedScopeID(ctx, 20); err != nil {
		t.Fatalf("CountByManagedScopeID: %v", err)
	}
	where = o.baseModel.lastCountOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-alpha")
	requireCondition(t, where, "managed_scope_id = ? AND deleted_at IS NULL", int64(20))
}
