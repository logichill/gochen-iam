package menu

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	"gochen/db"
	"gochen/db/orm"
)

type capturingModel struct {
	meta *orm.ModelMeta

	firstCalls        int
	findCalls         int
	createCalls       int
	saveCalls         int
	updateValuesCalls int
	deleteCalls       int

	lastUpdateValues map[string]any

	firstFn func(dest any) error
}

func (m *capturingModel) Meta() *orm.ModelMeta { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities {
	return nil
}

func (m *capturingModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	m.firstCalls++
	if m.firstFn != nil {
		return m.firstFn(dest)
	}
	return nil
}

func (m *capturingModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	m.findCalls++
	return nil
}

func (m *capturingModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	return 0, nil
}

func (m *capturingModel) Create(ctx context.Context, entities ...any) error {
	m.createCalls++
	return nil
}

func (m *capturingModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	m.saveCalls++
	return nil
}

func (m *capturingModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	m.updateValuesCalls++
	m.lastUpdateValues = values
	return nil
}

func (m *capturingModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	m.deleteCalls++
	return nil
}

func (m *capturingModel) Association(owner any, name string) orm.IAssociation { return nil }

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
func (o *fakeOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	return &fakeSession{parent: o}, nil
}
func (o *fakeOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
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

func TestMenuItemRepo_GetByIDWithDeleted_UsesTxSessionModel(t *testing.T) {
	o := &fakeOrm{
		baseModel:    &capturingModel{},
		sessionModel: &capturingModel{},
	}
	r, err := NewMenuItemRepository(o)
	if err != nil {
		t.Fatalf("NewMenuItemRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	if _, err := r.GetByIDWithDeleted(txCtx, 1); err != nil {
		t.Fatalf("GetByIDWithDeleted: %v", err)
	}

	if o.baseModel.firstCalls != 0 {
		t.Fatalf("expected base model not used, got firstCalls=%d", o.baseModel.firstCalls)
	}
	if o.sessionModel.firstCalls != 1 {
		t.Fatalf("expected session model used once, got firstCalls=%d", o.sessionModel.firstCalls)
	}
}

func TestMenuItemRepo_RestoreByID_UsesTxSessionModel(t *testing.T) {
	o := &fakeOrm{
		baseModel: &capturingModel{},
		sessionModel: &capturingModel{
			firstFn: func(dest any) error {
				item, ok := dest.(*iamentity.MenuItem)
				if !ok {
					return nil
				}
				at := time.Now().Add(-time.Hour)
				item.DeletedAt = &at
				item.UpdatedAt = at
				return nil
			},
		},
	}
	r, err := NewMenuItemRepository(o)
	if err != nil {
		t.Fatalf("NewMenuItemRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	if _, err := r.RestoreByID(txCtx, 1); err != nil {
		t.Fatalf("RestoreByID: %v", err)
	}

	if o.baseModel.updateValuesCalls != 0 {
		t.Fatalf("expected base model not used, got updateValuesCalls=%d", o.baseModel.updateValuesCalls)
	}
	if o.sessionModel.updateValuesCalls != 1 {
		t.Fatalf("expected session model UpdateValues called once, got updateValuesCalls=%d", o.sessionModel.updateValuesCalls)
	}

	v, ok := o.sessionModel.lastUpdateValues["deleted_at"]
	if !ok {
		t.Fatalf("expected UpdateValues includes deleted_at")
	}
	if v != nil {
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Pointer || !rv.IsNil() {
			t.Fatalf("expected deleted_at to be nil, got %T", v)
		}
	}
	if _, ok := o.sessionModel.lastUpdateValues["updated_at"]; !ok {
		t.Fatalf("expected UpdateValues includes updated_at")
	}
}
