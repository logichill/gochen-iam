package tenant

import (
	"context"
	"database/sql"
	"fmt"
	coredialect "gochen/db/dialect"
	"gochen/testkit"
	"testing"

	"gochen-runtime/db/dialect"
	"gochen/db"
	"gochen/db/orm"
	"gochen/domain/spec"
)

type capturingModel struct {
	meta *orm.ModelMeta

	firstCalls int
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) Dialect() coredialect.IDialect  { return dialect.New("") }
func (m *capturingModel) Count(context.Context, ...orm.QueryOption) (int64, error) {
	return 0, nil
}
func (m *capturingModel) First(context.Context, any, ...orm.QueryOption) error {
	m.firstCalls++
	return nil
}
func (m *capturingModel) Find(context.Context, any, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Create(context.Context, ...any) error                { return nil }
func (m *capturingModel) Save(context.Context, any, ...orm.QueryOption) error { return nil }
func (m *capturingModel) UpdateValues(context.Context, map[string]any, ...orm.QueryOption) error {
	return nil
}
func (m *capturingModel) Delete(context.Context, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Association(any, string) orm.IAssociation         { return nil }

type fakeResult struct{ rows int64 }

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return r.rows, nil }

func (m *capturingModel) SaveWithResult(context.Context, any, ...orm.QueryOption) (sql.Result, error) {
	return fakeResult{rows: 1}, nil
}
func (m *capturingModel) UpdateValuesWithResult(context.Context, map[string]any, ...orm.QueryOption) (sql.Result, error) {
	return fakeResult{rows: 1}, nil
}
func (m *capturingModel) DeleteWithResult(context.Context, ...orm.QueryOption) (sql.Result, error) {
	return fakeResult{rows: 1}, nil
}

type fakeOrm struct {
	baseModel    *capturingModel
	sessionModel *capturingModel
}

func (o *fakeOrm) DatasourceID() string { return fmt.Sprintf("iam-tenant-test:%p", o) }

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

func TestTenantRepo_Get_UsesTxSessionModel(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewTenantRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
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
