package role

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	"gochen/db"
	"gochen/db/orm"
)

type capturingModel struct {
	meta *orm.ModelMeta

	findCalls int
	findFn    func(dest any) error
}

func (m *capturingModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingModel) First(context.Context, any, ...orm.QueryOption) error {
	return nil
}
func (m *capturingModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	m.findCalls++
	if m.findFn != nil {
		return m.findFn(dest)
	}
	return nil
}
func (m *capturingModel) Count(context.Context, ...orm.QueryOption) (int64, error) { return 0, nil }
func (m *capturingModel) Create(context.Context, ...any) error                     { return nil }
func (m *capturingModel) Save(context.Context, any, ...orm.QueryOption) error      { return nil }
func (m *capturingModel) UpdateValues(context.Context, map[string]any, ...orm.QueryOption) error {
	return nil
}
func (m *capturingModel) Delete(context.Context, ...orm.QueryOption) error { return nil }
func (m *capturingModel) Association(any, string) orm.IAssociation         { return nil }

type fakeOrm struct {
	baseRoleModel *capturingModel

	sessionRoleModel      *capturingModel
	sessionUserRoleModel  *capturingModel
	sessionGroupRoleModel *capturingModel
}

func (o *fakeOrm) Capabilities() orm.Capabilities           { return nil }
func (o *fakeOrm) WithContext(ctx context.Context) orm.IOrm { return o }
func (o *fakeOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	o.baseRoleModel.meta = meta
	return o.baseRoleModel, nil
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
	switch meta.Table {
	case "roles":
		s.parent.sessionRoleModel.meta = meta
		return s.parent.sessionRoleModel, nil
	case "user_roles":
		s.parent.sessionUserRoleModel.meta = meta
		return s.parent.sessionUserRoleModel, nil
	case "group_roles":
		s.parent.sessionGroupRoleModel.meta = meta
		return s.parent.sessionGroupRoleModel, nil
	default:
		return &capturingModel{meta: meta}, nil
	}
}
func (s *fakeSession) Begin(ctx context.Context) (orm.IOrmSession, error) { return s, nil }
func (s *fakeSession) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	return s, nil
}
func (s *fakeSession) Database() db.IDatabase { return nil }
func (s *fakeSession) Raw() any               { return nil }
func (s *fakeSession) Commit() error          { return nil }
func (s *fakeSession) Rollback() error        { return nil }

func TestRoleRepo_GetRoleUsageStats_UsesTxSessionEngineModels(t *testing.T) {
	roleModel := &capturingModel{
		findFn: func(dest any) error {
			rv := reflect.ValueOf(dest)
			if rv.Kind() != reflect.Pointer {
				return nil
			}
			sv := rv.Elem()
			if sv.Kind() != reflect.Slice {
				return nil
			}
			elemType := sv.Type().Elem()
			elem := reflect.New(elemType).Elem()

			if f := elem.FieldByName("ID"); f.IsValid() && f.CanSet() && f.Kind() == reflect.Int64 {
				f.SetInt(1)
			}
			if f := elem.FieldByName("Name"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
				f.SetString("role")
			}
			if f := elem.FieldByName("Status"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
				f.SetString("active")
			}
			sv.Set(reflect.Append(sv, elem))
			return nil
		},
	}

	o := &fakeOrm{
		baseRoleModel:         &capturingModel{},
		sessionRoleModel:      roleModel,
		sessionUserRoleModel:  &capturingModel{},
		sessionGroupRoleModel: &capturingModel{},
	}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	txCtx, err := orm.WithTxSession(context.Background(), &fakeSession{parent: o}, true)
	if err != nil {
		t.Fatalf("WithTxSession: %v", err)
	}
	if _, err := r.GetRoleUsageStats(txCtx); err != nil {
		t.Fatalf("GetRoleUsageStats: %v", err)
	}

	if o.baseRoleModel.findCalls != 0 {
		t.Fatalf("expected base model not used, got findCalls=%d", o.baseRoleModel.findCalls)
	}
	if o.sessionRoleModel.findCalls != 1 {
		t.Fatalf("expected roles query on session model, got findCalls=%d", o.sessionRoleModel.findCalls)
	}
	if o.sessionUserRoleModel.findCalls != 1 {
		t.Fatalf("expected user_roles query on session model, got findCalls=%d", o.sessionUserRoleModel.findCalls)
	}
	if o.sessionGroupRoleModel.findCalls != 1 {
		t.Fatalf("expected group_roles query on session model, got findCalls=%d", o.sessionGroupRoleModel.findCalls)
	}
}
