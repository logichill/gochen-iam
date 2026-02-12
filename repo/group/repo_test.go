package group

import (
	"context"
	"database/sql"
	"testing"

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

	lastAssociation *capturingAssociation
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) First(context.Context, any, ...orm.QueryOption) error {
	m.firstCalls++
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

func TestGroupRepo_GetByID_UsesTxSessionModel(t *testing.T) {
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
	if _, err := r.GetByID(txCtx, 1); err != nil {
		t.Fatalf("GetByID: %v", err)
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
