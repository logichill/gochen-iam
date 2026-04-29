package group

import (
	"context"
	"database/sql"
	"testing"

	iamentity "gochen-iam/entity"
	auth "gochen/auth/core"
	"gochen/contextx"
	"gochen/db"
	"gochen/db/orm"
)

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

	firstFn          func(dest any) error
	firstCalls       int
	associationCalls int
	lastFirstOpts    orm.QueryOptions

	lastAssociation *capturingAssociation
	savedEntity     any
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) First(_ context.Context, dest any, opts ...orm.QueryOption) error {
	m.firstCalls++
	m.lastFirstOpts = orm.CollectQueryOptions(opts...)
	if m.firstFn != nil {
		return m.firstFn(dest)
	}
	return nil
}
func (m *capturingModel) Find(context.Context, any, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Count(context.Context, ...orm.QueryOption) (int64, error) {
	return 0, nil
}
func (m *capturingModel) Create(context.Context, ...any) error { return nil }
func (m *capturingModel) Save(_ context.Context, entity any, _ ...orm.QueryOption) error {
	m.savedEntity = entity
	return nil
}
func (m *capturingModel) UpdateValues(context.Context, map[string]any, ...orm.QueryOption) error {
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
	derived, err := auth.WithPrincipal(ctx, auth.Principal{SubjectID: 1, ActiveScopeID: 1})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	derived, err = contextx.WithTenantID(derived, tenantID)
	if err != nil {
		t.Fatalf("WithTenantID: %v", err)
	}
	return derived
}

func TestGroupRepo_Get_UsesTxSessionModel(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewGroupRepository(o)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	txCtx = withTenantPrincipal(t, txCtx, "tenant-a")
	if _, err := r.Get(txCtx, 1); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if o.baseModel.firstCalls != 0 {
		t.Fatalf("expected base model not used, got firstCalls=%d", o.baseModel.firstCalls)
	}
	if o.sessionModel.firstCalls != 1 {
		t.Fatalf("expected session model used once, got firstCalls=%d", o.sessionModel.firstCalls)
	}
}

func TestGroupRepo_AddUserToGroup_UsesTxSessionAssociation(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewGroupRepository(o)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	txCtx = withTenantPrincipal(t, txCtx, "tenant-a")
	if err := r.AddUserToGroup(txCtx, 1, 2); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}

	if o.baseModel.associationCalls != 0 {
		t.Fatalf("expected base model association not used, got associationCalls=%d", o.baseModel.associationCalls)
	}
	if o.sessionModel.associationCalls != 1 {
		t.Fatalf("expected session model association used once, got associationCalls=%d", o.sessionModel.associationCalls)
	}
	if o.sessionModel.lastAssociation == nil || o.sessionModel.lastAssociation.appendCalls != 1 {
		t.Fatalf("expected association Append called once")
	}
}

func TestGroupRepo_Get_FiltersByTenantFromPrincipal(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewGroupRepository(o)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.Get(ctx, 7); err != nil {
		t.Fatalf("Get: %v", err)
	}

	where := o.baseModel.lastFirstOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-a")
	requireCondition(t, where, "id = ?", int64(7))
	requireCondition(t, where, "deleted_at IS NULL")
}

func TestGroupRepo_Update_StripsAssociationsBeforeSave(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewGroupRepository(o)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}

	group := &iamentity.Group{
		TenantID:       "tenant-a",
		ManagedScopeID: 1,
		OwnerID:        "tenant:tenant-a",
		Name:           "ops",
		ParentID:       nil,
		Parent:         &iamentity.Group{},
		Children:       []*iamentity.Group{{}},
		Users:          []*iamentity.User{{}},
		DefaultRoles:   []*iamentity.Role{{}},
	}
	group.SetID(7)

	o.sessionModel.firstFn = func(dest any) error {
		if target, ok := dest.(**iamentity.Group); ok {
			*target = &iamentity.Group{}
			(*target).SetID(7)
			return nil
		}
		return nil
	}
	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if err := r.Update(ctx, group); err != nil {
		t.Fatalf("Update: %v", err)
	}

	saved, ok := o.sessionModel.savedEntity.(*iamentity.Group)
	if !ok || saved == nil {
		t.Fatalf("expected saved group entity, got %#v", o.sessionModel.savedEntity)
	}
	if saved == group {
		t.Fatal("expected update to save a detached copy")
	}
	if saved.Parent != nil || saved.Children != nil || saved.Users != nil || saved.DefaultRoles != nil {
		t.Fatalf("expected associations stripped before save, got parent=%v children=%v users=%v roles=%v", saved.Parent, saved.Children, saved.Users, saved.DefaultRoles)
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
