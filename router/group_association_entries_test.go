package router

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gochen/testkit"
)

func TestGroupTreeActualHTTPWithRuntimeSQLite(t *testing.T) {
	_, storage, scopes := scopeRoutesFixture(t)
	groups, err := grouprepo.NewGroupRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := svc.NewIAMAccess(nil)
	service, err := groupsvc.NewGroupService(groups, users, roles, nil, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewGroupRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	g := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: 1, OwnerID: "tenant:tenant-a", Name: "root", Level: 1, Path: "/1"}
	g.SetID(1)
	if err := storage.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	for i, scope := range []int64{1, 2} {
		u := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: scope, HomeTenantID: "tenant-a", HomeScopeID: scope, OwnerID: "tenant:tenant-a", Username: []string{"visible", "hidden"}[i], Email: []string{"visible@example.com", "hidden@example.com"}[i], Status: "active"}
		u.SetID(int64(i + 1))
		if err := storage.Create(u).Error; err != nil {
			t.Fatal(err)
		}
		if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", u.GetID(), 1).Error; err != nil {
			t.Fatal(err)
		}
	}
	namespace := &iamentity.Scope{Key: "tenant-a", Name: "tenant namespace", Type: "tenant", Path: "/tenant-a/"}
	namespace.SetID(1)
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 1, OwnerID: "tenant:tenant-a", Name: "member-role"}
	role.SetID(1)
	for _, item := range []any{namespace, role, &iamentity.UserRoleBinding{UserID: 1, RoleID: 1, GrantScopeID: 1}} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Exec("INSERT INTO group_roles (group_id, role_id) VALUES (1, 1)").Error; err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"group:api:manage", "group:api:read"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/iam/groups/tree", nil).WithContext(ctx))
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"user_count":1`) || !strings.Contains(recorder.Body.String(), `"name":"root"`) {
		t.Fatalf("actual tree status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, entry := range []struct {
		path, expected string
	}{
		{"/roots", `"name":"root"`},
		{"/search/by-level?level=1", `"name":"root"`},
		{"/1/users", `"username":"visible"`},
		{"/1/roles", `"name":"tenant namespace"`},
	} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/iam/groups"+entry.path, nil).WithContext(ctx))
		if response.Code != 200 || !strings.Contains(response.Body.String(), entry.expected) || strings.Contains(response.Body.String(), `"username":"hidden"`) {
			t.Fatalf("actual %s status=%d body=%s", entry.path, response.Code, response.Body.String())
		}
	}
}

func groupAssociationRoutesFixture(t *testing.T) *GroupRoutes {
	t.Helper()
	_, _, scopes := scopeRoutesFixture(t)
	groups, err := grouprepo.NewGroupRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(scopes.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := svc.NewIAMAccess(nil)
	service, err := groupsvc.NewGroupService(groups, users, roles, nil, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewGroupRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	return routes
}

func TestGroupStatisticsBindsBothActualReadEntries(t *testing.T) {
	routes := groupAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/groups"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.setupGroupCustomRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	count, trees, declared, allowed, invalid := 0, 0, 0, 0, 0
	reads := map[string]int{}
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
		case auth.EntryAllowed:
			allowed++
		default:
			invalid++
		}
		if strings.Contains(entry.Entry.Key, "/statistics") && entry.Class == auth.EntryDeclared {
			count++
			if entry.Action != "http_statistics" || len(entry.Resources) != 2 || entry.ConditionPath == "" {
				t.Fatalf("statistics lacks three resource plans=%+v", entry)
			}
		}
		if strings.Contains(entry.Entry.Key, "/tree") && entry.Class == auth.EntryDeclared {
			trees++
			if entry.Action != "http_tree" || len(entry.Resources) != 1 || entry.ConditionPath == "" {
				t.Fatalf("tree lacks group/membership plans=%+v", entry)
			}
		}
		for _, action := range []string{"roots", "by_level", "users", "roles"} {
			if entry.Action == "http_"+action+"_groups" {
				reads[action]++
				resourceCount := map[string]int{"roots": 2, "by_level": 1, "users": 3, "roles": 2}[action]
				if entry.Class != auth.EntryDeclared || len(entry.Resources) != resourceCount || entry.ConditionPath == "" {
					t.Fatalf("%s lacks every resource plan: %+v", action, entry)
				}
			}
		}
	}
	if count != 2 {
		t.Fatalf("declared statistics GET/HEAD=%d", count)
	}
	if trees != 2 {
		t.Fatalf("declared tree GET/HEAD=%d", trees)
	}
	for _, action := range []string{"roots", "by_level", "users", "roles"} {
		if reads[action] != 2 {
			t.Fatalf("%s declared GET/HEAD=%d", action, reads[action])
		}
	}
	if declared != 17 || allowed != 9 || invalid != 0 || len(server.Routes()) != 26 {
		t.Fatalf("custom group actual=%d declared=%d explicit_allow=%d invalid=%d", len(server.Routes()), declared, allowed, invalid)
	}
	t.Logf("custom group actual=%d declared=%d explicit_allow=%d pending=%d", len(server.Routes()), declared, allowed, invalid)
}

func TestGroupAssociationRoutesRequireDeclaredService(t *testing.T) {
	if _, err := NewGroupRoutes(nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing declaration error=%v", err)
	}
}

func TestGroupAssociationRoutesBindEveryActualEntry(t *testing.T) {
	routes := groupAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/groups"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerAssociationRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, entry := range entries.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
			if entry.Module != "iam" || entry.ResourceAccess != auth.ResourceAccessData || entry.ConditionPath == "" || len(entry.Resources) != 1 {
				t.Fatalf("missing association resource binding=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid entry=%+v", entry)
		}
	}
	if declared != 5 || allowed != 5 || len(server.Routes()) != 10 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	t.Logf("association actual=%d declared=%d explicit_allow=%d invalid=0", len(server.Routes()), declared, allowed)
}
