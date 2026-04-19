package tenant

import (
	"context"
	"database/sql"
	"testing"

	iamauth "gochen-iam/auth"
	iammw "gochen-iam/middleware"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen/auth"
	"gochen/db"
	"gochen/db/orm"
)

type capturingTenantModel struct {
	meta     *orm.ModelMeta
	lastOpts orm.QueryOptions
}

func (m *capturingTenantModel) Meta() *orm.ModelMeta           { return m.meta }
func (m *capturingTenantModel) Capabilities() orm.Capabilities { return nil }
func (m *capturingTenantModel) First(context.Context, any, ...orm.QueryOption) error {
	return nil
}
func (m *capturingTenantModel) Find(_ context.Context, _ any, opts ...orm.QueryOption) error {
	m.lastOpts = orm.CollectQueryOptions(opts...)
	return nil
}
func (m *capturingTenantModel) Count(context.Context, ...orm.QueryOption) (int64, error) {
	return 0, nil
}
func (m *capturingTenantModel) Create(context.Context, ...any) error                { return nil }
func (m *capturingTenantModel) Save(context.Context, any, ...orm.QueryOption) error { return nil }
func (m *capturingTenantModel) UpdateValues(context.Context, map[string]any, ...orm.QueryOption) error {
	return nil
}
func (m *capturingTenantModel) Delete(context.Context, ...orm.QueryOption) error { return nil }
func (m *capturingTenantModel) Association(any, string) orm.IAssociation         { return nil }

type fakeTenantOrm struct {
	model *capturingTenantModel
}

func (o *fakeTenantOrm) Capabilities() orm.Capabilities       { return nil }
func (o *fakeTenantOrm) WithContext(context.Context) orm.IOrm { return o }
func (o *fakeTenantOrm) Database() db.IDatabase               { return nil }
func (o *fakeTenantOrm) Raw() any                             { return nil }
func (o *fakeTenantOrm) Begin(context.Context) (orm.IOrmSession, error) {
	return nil, nil
}
func (o *fakeTenantOrm) BeginTx(context.Context, *sql.TxOptions) (orm.IOrmSession, error) {
	return nil, nil
}
func (o *fakeTenantOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	o.model.meta = meta
	return o.model, nil
}

func TestTenantService_ListTenants_FiltersSoftDeletedRows(t *testing.T) {
	model := &capturingTenantModel{}
	repo, err := tenantrepo.NewTenantRepository(&fakeTenantOrm{model: model})
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}

	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	authzRegistry, err := svc.NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := svc.NewIAMAuthorizer(nil, authzRegistry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}
	ctx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"api:tenant:*"},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iammw.ScopePlatform))

	service := NewTenantService(repo, nil, authorizer)
	if _, err := service.ListTenants(ctx); err != nil {
		t.Fatalf("ListTenants: %v", err)
	}

	where := model.lastOpts.Where
	if len(where) != 1 {
		t.Fatalf("expected one where condition, got %d", len(where))
	}
	if where[0].Expr != "deleted_at IS NULL" {
		t.Fatalf("unexpected where expr: %s", where[0].Expr)
	}
}
