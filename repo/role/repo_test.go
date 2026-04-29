package role

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	iamentity "gochen-iam/entity"
	auth "gochen/auth/core"
	"gochen/contextx"
	"gochen/db"
	"gochen/db/orm"
)

type capturingModel struct {
	meta *orm.ModelMeta

	findCalls     int
	findFn        func(dest any) error
	firstFn       func(dest any) error
	firstCalls    int
	lastOpts      orm.QueryOptions
	lastFirstOpts orm.QueryOptions
	savedEntity   any
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
func (m *capturingModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	m.findCalls++
	m.lastOpts = orm.CollectQueryOptions(opts...)
	if m.findFn != nil {
		return m.findFn(dest)
	}
	return nil
}
func (m *capturingModel) Count(context.Context, ...orm.QueryOption) (int64, error) { return 0, nil }
func (m *capturingModel) Create(context.Context, ...any) error                     { return nil }
func (m *capturingModel) Save(_ context.Context, entity any, _ ...orm.QueryOption) error {
	m.savedEntity = entity
	return nil
}
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
	case "user_role_bindings":
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
	txCtx = withTenantPrincipal(t, txCtx, "tenant-a")
	if _, err := r.RoleUsageStats(txCtx); err != nil {
		t.Fatalf("RoleUsageStats: %v", err)
	}

	if o.baseRoleModel.findCalls != 0 {
		t.Fatalf("expected base model not used, got findCalls=%d", o.baseRoleModel.findCalls)
	}
	if o.sessionRoleModel.findCalls != 1 {
		t.Fatalf("expected roles query on session model, got findCalls=%d", o.sessionRoleModel.findCalls)
	}
	if o.sessionUserRoleModel.findCalls != 1 {
		t.Fatalf("expected user_role_bindings query on session model, got findCalls=%d", o.sessionUserRoleModel.findCalls)
	}
	if o.sessionGroupRoleModel.findCalls != 1 {
		t.Fatalf("expected group_roles query on session model, got findCalls=%d", o.sessionGroupRoleModel.findCalls)
	}
}

func TestRoleRepo_FindByNames_FiltersByTenant(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.FindByNames(ctx, []string{"admin", "viewer"}); err != nil {
		t.Fatalf("FindByNames: %v", err)
	}

	where := o.baseRoleModel.lastOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-a")
	requireCondition(t, where, "name IN ?", []string{"admin", "viewer"})
	requireCondition(t, where, "deleted_at IS NULL")
}

func TestRoleRepo_FindUserRoles_FiltersByTenant(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.FindUserRoles(ctx); err != nil {
		t.Fatalf("FindUserRoles: %v", err)
	}

	where := o.baseRoleModel.lastOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-a")
	requireCondition(t, where, "is_system = ?", false)
	requireCondition(t, where, "deleted_at IS NULL")
}

func TestRoleRepo_FindByPermission_FiltersByTenant(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.FindByPermission(ctx, ""); err != nil {
		t.Fatalf("FindByPermission: %v", err)
	}

	where := o.baseRoleModel.lastOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-a")
	requireCondition(t, where, "deleted_at IS NULL")
}

func TestRoleRepo_Get_FiltersByTenantFromPrincipal(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.Get(ctx, 7); err != nil {
		t.Fatalf("Get: %v", err)
	}

	where := o.baseRoleModel.lastFirstOpts.Where
	requireCondition(t, where, "tenant_id = ?", "tenant-a")
	requireCondition(t, where, "id = ?", int64(7))
	requireCondition(t, where, "deleted_at IS NULL")
}

func TestRoleRepo_Update_StripsAssociationsBeforeSave(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}

	role := &iamentity.Role{
		TenantID:         "tenant-a",
		OwnerID:          "tenant:tenant-a",
		NamespaceScopeID: 1,
		Users:            []iamentity.User{{}},
		Groups:           []iamentity.Group{{}},
		NamespaceScope:   &iamentity.Scope{},
	}
	role.SetID(7)

	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if err := r.Update(ctx, role); err != nil {
		t.Fatalf("Update: %v", err)
	}

	saved, ok := o.baseRoleModel.savedEntity.(*iamentity.Role)
	if !ok || saved == nil {
		t.Fatalf("expected saved role entity, got %#v", o.baseRoleModel.savedEntity)
	}
	if saved == role {
		t.Fatal("expected update to save a detached copy")
	}
	if saved.Users != nil || saved.Groups != nil || saved.NamespaceScope != nil {
		t.Fatalf("expected associations stripped before save, got users=%v groups=%v scope=%v", saved.Users, saved.Groups, saved.NamespaceScope)
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
			if !reflect.DeepEqual(condition.Args[i], wantArgs[i]) {
				t.Fatalf("unexpected arg %d for %q: %#v", i, expr, condition.Args)
			}
		}
		return
	}
	t.Fatalf("condition %q not found in %#v", expr, conditions)
}
