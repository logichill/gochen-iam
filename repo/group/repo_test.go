package group

import (
	"context"
	"database/sql"
	"testing"

	"gochen/authz"
	ctxx "gochen/contextx"
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

	firstCalls       int
	associationCalls int
	lastFirstOpts    orm.QueryOptions

	lastAssociation *capturingAssociation
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) First(_ context.Context, _ any, opts ...orm.QueryOption) error {
	m.firstCalls++
	m.lastFirstOpts = orm.CollectQueryOptions(opts...)
	return nil
}
func (m *capturingModel) Find(context.Context, any, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Count(context.Context, ...orm.QueryOption) (int64, error) {
	return 0, nil
}
func (m *capturingModel) Create(context.Context, ...any) error                { return nil }
func (m *capturingModel) Save(context.Context, any, ...orm.QueryOption) error { return nil }
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
	derived, err := authz.WithPrincipal(ctx, authz.Principal{SubjectID: 1, ActiveScopeID: 1})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	derived, err = ctxx.WithTenantID(derived, tenantID)
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
