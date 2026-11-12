package router

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestGroupCRUDActualHTTPBindingsAndLifecycle(t *testing.T) {
	_, storage, scopes := scopeRoutesFixture(t)
	groups, err := grouprepo.NewGroupRepository(scopes.Orm(), testkit.NewInt64Sequence(100))
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
	service, err := groupsvc.NewGroupService(groups, users, roles, nil, svc.NewIAMAccess(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewGroupRoutes(service)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
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
			if entry.Source == "" || entry.ConditionPath == "" {
				t.Fatalf("missing binding=%+v", entry)
			}
			switch entry.Action {
			case "create":
				if len(entry.Resources) != 2 {
					t.Fatalf("create lacks parent/name resources=%+v", entry)
				}
			case "update":
				if len(entry.Resources) != 4 || entry.Plan == nil {
					t.Fatalf("update lacks complete subtree resources=%+v", entry)
				}
				if _, ok := entry.Plan.Descriptor.Action("read"); !ok {
					t.Fatalf("initial PUT read has no primary plan=%+v", entry)
				}
			case "delete":
				if len(entry.Resources) != 2 {
					t.Fatalf("delete lacks existence resources=%+v", entry)
				}
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("unbound Group HTTP=%+v", entry)
		}
	}
	if len(server.Routes()) != 39 || declared != 27 || allowed != 12 {
		t.Fatalf("incomplete actual group routes=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	t.Logf("complete Group HTTP actual=%d declared=%d explicit_allow=%d invalid=0", len(server.Routes()), declared, allowed)
	ctx, err := contextx.WithTenantID(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"group:api:manage", "group:api:read", "group:api:write", "group:api:delete"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, status int) string {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/iam/groups"+path, strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != status {
			t.Fatalf("%s %s status=%d body=%s", method, path, recorder.Code, recorder.Body.String())
		}
		return recorder.Body.String()
	}
	trusted := ctx
	var accesses atomic.Int64
	countAccess := func(*gorm.DB) { accesses.Add(1) }
	for _, register := range []func(string, func(*gorm.DB)) error{
		storage.Callback().Query().Before("gorm:query").Register,
		storage.Callback().Create().Before("gorm:create").Register,
		storage.Callback().Update().Before("gorm:update").Register,
		storage.Callback().Delete().Before("gorm:delete").Register,
	} {
		if err := register("group-http:count-access", countAccess); err != nil {
			t.Fatal(err)
		}
	}
	for _, denied := range []struct {
		subject, scope, method, path, body string
		permissions                        []string
	}{
		{"7", "platform", "POST", "", `{"name":"denied"}`, []string{"group:api:write"}},
		{"not-numeric", "platform", "POST", "", `{"name":"denied"}`, []string{"group:api:manage", "group:api:write"}},
		{"7", "family", "POST", "", `{"name":"denied"}`, []string{"group:api:manage", "group:api:write"}},
		{"7", "platform", "POST", "", `{"name":"denied"}`, []string{"group:api:manage", "group:api:read"}},
		{"7", "platform", "GET", "", "", []string{"group:api:manage", "group:api:write"}},
		{"7", "platform", "DELETE", "/100", "", []string{"group:api:manage", "group:api:read"}},
	} {
		ctx, err = hostauthz.WithPrincipal(trusted, hostauthz.Principal{SubjectID: denied.subject, ActiveScopeID: 1, Permissions: denied.permissions})
		if err != nil {
			t.Fatal(err)
		}
		ctx = iamauth.BindActiveScopeContext(ctx, 1, denied.scope)
		accesses.Store(0)
		status := 403
		if denied.subject == "not-numeric" {
			status = 401
		}
		request(denied.method, denied.path, denied.body, status)
		if accesses.Load() != 0 {
			t.Fatalf("denied %s %s accessed resources %d times", denied.method, denied.path, accesses.Load())
		}
	}
	ctx = trusted
	request("POST", "", `{"name":"root"}`, 200)
	request("POST", "", `{"name":"other-root"}`, 200)
	request("POST", "", `{"name":"child","parent_id":100}`, 200)
	request("POST", "", `{"name":"grandchild","parent_id":102}`, 200)
	request("PUT", "/102", `{"version":0,"parent_id":101}`, 200)
	request("PUT", "/102", `{"version":0,"description":"stale"}`, 409)
	request("PUT", "/102", `{"version":1,"managed_scope_id":2}`, 403)
	var child, grandchild iamentity.Group
	if err := storage.First(&child, 102).Error; err != nil {
		t.Fatal(err)
	}
	if err := storage.First(&grandchild, 103).Error; err != nil {
		t.Fatal(err)
	}
	if child.Path != "/101/102" || grandchild.Path != "/101/102/103" || grandchild.GetVersion() != 1 || child.ManagedScopeID != 1 {
		t.Fatalf("incorrect actual subtree child=%+v grandchild=%+v", child, grandchild)
	}
	request("DELETE", "/101", "", 400)
	u := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 2, HomeTenantID: "tenant-a", HomeScopeID: 2, Username: "hidden", Email: "hidden@example.com"}
	u.SetID(1)
	if err := storage.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (1, 103)").Error; err != nil {
		t.Fatal(err)
	}
	request("DELETE", "/103", "", 400)
	if err := storage.Exec("DELETE FROM user_groups WHERE user_id = 1 AND group_id = 103").Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{103, 102, 101} {
		request("DELETE", fmt.Sprintf("/%d", id), "", 200)
		var stored iamentity.Group
		if err := storage.First(&stored, id).Error; err != nil || stored.DeletedAt == nil {
			t.Fatalf("expected retained soft deletion id=%d value=%+v error=%v", id, stored, err)
		}
	}
	request("GET", "/100", "", 200)
	request("POST", "/bulk", `[{"name":"batch-duplicate"},{"name":"batch-duplicate"}]`, 400)
	var duplicateCount int64
	if err := storage.Model(&iamentity.Group{}).Where("name = ?", "batch-duplicate").Count(&duplicateCount).Error; err != nil || duplicateCount != 0 {
		t.Fatalf("failed batch create left rows=%d error=%v", duplicateCount, err)
	}
	request("POST", "/bulk", `[{"name":"batch-a"},{"name":"batch-b"}]`, 200)
	var batch []*iamentity.Group
	if err := storage.Where("name IN ?", []string{"batch-a", "batch-b"}).Order("name").Find(&batch).Error; err != nil || len(batch) != 2 {
		t.Fatalf("batch create rows=%+v error=%v", batch, err)
	}
	a, b := batch[0].GetID(), batch[1].GetID()
	request("PUT", "/bulk", fmt.Sprintf(`[{"id":%d,"version":0,"name":"updated-a"},{"id":%d,"version":0,"name":"updated-b"}]`, a, b), 200)
	request("PUT", "/bulk", fmt.Sprintf(`[{"id":%d,"version":1,"name":"rolled-back"},{"id":%d,"version":0,"name":"stale-b"}]`, a, b), 409)
	var retained iamentity.Group
	if err := storage.First(&retained, a).Error; err != nil || retained.Name != "updated-a" || retained.GetVersion() != 1 {
		t.Fatalf("failed batch update changed first row=%+v error=%v", retained, err)
	}
	request("POST", "", fmt.Sprintf(`{"name":"batch-child","parent_id":%d}`, b), 200)
	request("DELETE", "/bulk", fmt.Sprintf(`{"ids":[%d,%d]}`, a, b), 400)
	for _, id := range []int64{a, b} {
		var stored iamentity.Group
		if err := storage.First(&stored, id).Error; err != nil || stored.DeletedAt != nil {
			t.Fatalf("failed batch deletion changed row=%+v error=%v", stored, err)
		}
	}
	var leaf iamentity.Group
	if err := storage.Where("name = ?", "batch-child").First(&leaf).Error; err != nil {
		t.Fatal(err)
	}
	request("DELETE", fmt.Sprintf("/%d", leaf.GetID()), "", 200)
	request("DELETE", "/bulk", fmt.Sprintf(`{"ids":[%d,%d]}`, a, b), 200)
}
