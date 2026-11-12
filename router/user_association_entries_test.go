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
	usersvc "gochen-iam/service/user"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func userAssociationRoutesFixture(t *testing.T) (*UserRoutes, *gorm.DB) {
	t.Helper()
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
	service, err := usersvc.NewUserService(users, groups, roles, nil, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewUserRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	return routes, storage
}

func TestUserAssociationReadsBindActualHTTPEntries(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerAssociationReadRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, status := range registry.Report() {
		switch status.Class {
		case auth.EntryDeclared:
			declared++
			count := 2
			if strings.Contains(status.Entry.Key, "/groups") {
				count = 3
			}
			if status.Module != "iam" || status.ResourceAccess != auth.ResourceAccessData || status.ConditionPath == "" || len(status.Resources) != count {
				t.Fatalf("incomplete association plans=%+v", status)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid entry=%+v", status)
		}
	}
	if declared != 4 || allowed != 2 || len(server.Routes()) != 6 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	t.Logf("user association reads actual=6 declared=4 explicit_allow=2 invalid=0")
	missing := hostauthz.NewEntryRegistry()
	if err := missing.ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound actual entries passed the gate")
	}
}

func TestUserAssociationReadsUseDeclarationsOnRealHTTP(t *testing.T) {
	routes, storage := userAssociationRoutesFixture(t)
	user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	namespace := &iamentity.Scope{Key: "namespace", Name: "visible namespace", Type: "tenant", Path: "/namespace/"}
	namespace.ID = 1
	for _, item := range []any{user, namespace} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"visible", "hidden"} {
		scopeID, id := int64(i+1), int64(i+100)
		group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: scopeID, OwnerID: "owner", Name: name}
		group.ID = id
		role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: scopeID, OwnerID: "owner", Name: name}
		role.ID = id
		for _, item := range []any{group, role, &iamentity.UserRoleBinding{UserID: user.ID, RoleID: id, GrantScopeID: 1, Status: "active"}} {
			if err := storage.Create(item).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, id).Error; err != nil {
			t.Fatal(err)
		}
	}
	principal := func(permissions []string, kind string) context.Context {
		t.Helper()
		ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: permissions})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, 1, kind)
		ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ctx  context.Context
		code int
	}{
		{t.Context(), 401},
		{principal([]string{"user:api:manage"}, "platform"), 403},
		{principal([]string{"user:api:read"}, "platform"), 403},
		{principal([]string{"*:*:*"}, "department"), 403},
		{principal([]string{"user:api:read", "user:api:manage"}, "platform"), 200},
	} {
		for _, path := range []string{"/iam/users/99/roles", "/iam/users/99/groups"} {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", path, nil).WithContext(test.ctx))
			if recorder.Code != test.code {
				t.Fatalf("%s status=%d want=%d body=%s", path, recorder.Code, test.code, recorder.Body.String())
			}
			if test.code == 200 && (!strings.Contains(recorder.Body.String(), `"name":"visible"`) || strings.Contains(recorder.Body.String(), `"name":"hidden"`)) {
				t.Fatalf("%s leaked resources: %s", path, recorder.Body.String())
			}
		}
	}
}

func TestUserRoutesRequireDeclaredService(t *testing.T) {
	if _, err := NewUserRoutes(nil); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("missing service=%v", err)
	}
}
