package router

import (
	"path/filepath"
	"testing"

	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	scopesvc "gochen-iam/service/scope"
	"gochen-runtime/db/orm/lite"
	"gochen-runtime/db/sql/stdsql"
	"gochen/db"
	"gochen/testkit"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func scopeRoutesFixture(t *testing.T) (*ScopeRoutes, *gorm.DB, *scoperepo.ScopeRepo) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope-routes.db")
	storage, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.AutoMigrate(&iamentity.Scope{}, &iamentity.ScopeVisibility{}, &iamentity.Tenant{}, &iamentity.Role{}, &iamentity.User{}, &iamentity.Group{}, &iamentity.UserRoleBinding{}); err != nil {
		t.Fatal(err)
	}
	conn, err := storage.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	database, err := stdsql.NewWithContext(t.Context(), db.DBConfig{Driver: "sqlite3", Database: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	engine, err := lite.New(database)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenantrepo.NewTenantRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	groups, err := grouprepo.NewGroupRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	service, err := scopesvc.NewScopeService(scopes, tenants, roles, users, groups)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewScopeRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	return routes, storage, scopes
}

func TestScopeRoutes_RegisterRoutes(t *testing.T) {
	routes := map[string]struct{}{}
	root := newRecordingGroup("", routes)

	sr, _, _ := scopeRoutesFixture(t)
	if err := sr.RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}

	want := []string{
		"GET /scopes",
		"GET /scopes/:id/visibility",
		"POST /scopes",
		"PUT /scopes/:id",
		"POST /scopes/:id/activate",
		"POST /scopes/:id/deactivate",
		"POST /scopes/:id/repair",
		"DELETE /scopes/:id",
	}
	for _, route := range want {
		if _, ok := routes[route]; !ok {
			t.Fatalf("missing route: %s", route)
		}
	}
}

func TestToScopeListItem_ProjectsGovernanceHealthState(t *testing.T) {
	parentID := int64(100)
	scope := &iamentity.Scope{
		Key:      "shanghai",
		Name:     "Shanghai",
		Type:     "city",
		ParentID: &parentID,
		Path:     "/platform/cn/shanghai/",
		Depth:    3,
		Status:   iamentity.ScopeStatusInactive,
	}
	scope.SetID(101)
	governance := &svc.ScopeGovernanceState{
		ChildCount:        0,
		CanDelete:         true,
		HealthStatus:      "drifted",
		HealthReason:      "当前授权域的 path/depth 与父授权域不一致，可执行修复。",
		CanRepair:         true,
		DeleteBlockReason: "",
	}

	item := toScopeListItem(scope, governance)

	if item.ID != 101 || item.ParentID == nil || *item.ParentID != parentID {
		t.Fatalf("unexpected scope identity projection: %+v", item)
	}
	if item.HealthStatus != "drifted" {
		t.Fatalf("expected health status drifted, got %q", item.HealthStatus)
	}
	if item.HealthReason != governance.HealthReason {
		t.Fatalf("expected health reason %q, got %q", governance.HealthReason, item.HealthReason)
	}
	if !item.CanRepair {
		t.Fatalf("expected can_repair=true, got %+v", item)
	}
	if !item.CanDelete {
		t.Fatalf("expected can_delete=true, got %+v", item)
	}
}
