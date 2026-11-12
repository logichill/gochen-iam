package role

import (
	"context"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestRoleCRUDAndDirectoriesRejectBeforeQueries(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	var reads atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("role-crud:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{context.Background(), roleWritePrincipal(t, env, "7", "tenant", "other:api:read")} {
		for _, call := range []func() error{
			func() error {
				_, e := env.roleService.CreateRole(ctx, &svc.CreateRoleRequest{TenantID: env.tenantID, Name: "valid-name", Permissions: []string{"role:api:read"}})
				return e
			},
			func() error {
				_, e := env.roleService.UpdateRole(ctx, 1, &svc.UpdateRoleRequest{Name: "changed"})
				return e
			},
			func() error { return env.roleService.DeleteRole(ctx, 1) },
			func() error { return env.roleService.AssignRoleToGroup(ctx, 1, 2) },
			func() error { return env.roleService.RemoveRoleFromGroup(ctx, 1, 2) },
			func() error { _, e := env.roleService.SearchRoles(ctx, "x", 10); return e },
			func() error { _, e := env.roleService.ActiveRoles(ctx); return e },
			func() error { _, e := env.roleService.RoleGroups(ctx, 1); return e },
			func() error {
				_, e := env.roleService.CheckPermission(ctx, &svc.PermissionCheckRequest{UserID: 1, Permission: "test:api:read"})
				return e
			},
		} {
			if err := call(); err == nil {
				t.Fatal("denied service call succeeded")
			}
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("denied calls queried %d times", reads.Load())
	}
}

func TestRoleNameInvariantIncludesHiddenNamespace(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	visible := env.createTestRole(t, "visible")
	hidden := env.createTestRole(t, "reserved-name")
	if err := env.db.Model(hidden).Update("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write")
	_, err := env.roleService.UpdateRole(ctx, visible.ID, &svc.UpdateRoleRequest{Name: hidden.Name, Permissions: []string{"role:api:read"}})
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("hidden namespace duplicate: %v", err)
	}
	stored, err := env.roleRepo.Repo.Get(env.backgroundCtx, visible.ID, spec.All())
	if err != nil || stored.Name != "visible" || stored.Version != visible.Version {
		t.Fatalf("failed name validation wrote state: %+v %v", stored, err)
	}
}

func TestRoleDeleteChecksCompleteReferencesAndRollsBackBulk(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	first := env.createTestRole(t, "first")
	referenced := env.createTestRole(t, "referenced")
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 2, ManagedScopeID: 2, OwnerID: "outside", Username: "outside", Email: "outside@example.com", Status: "active"}
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: referenced.ID, GrantScopeID: 2, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:delete", "role:api:manage")
	if err := env.roleService.HTTPApplication().DeleteBulk(ctx, []int64{first.ID, referenced.ID}); !errors.Is(err, errors.Validation) {
		t.Fatalf("hidden user reference: %v", err)
	}
	stored, err := env.roleRepo.Repo.Get(env.backgroundCtx, first.ID, spec.All())
	if err != nil || stored.Version != first.Version || stored.IsDeleted() {
		t.Fatalf("batch rollback lost first role: %+v %v", stored, err)
	}
	if err := env.db.Where("role_id = ?", referenced.ID).Delete(&iamentity.UserRoleBinding{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec("INSERT INTO group_roles (group_id, role_id) VALUES (?, ?)", 999, referenced.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.roleService.DeleteRole(ctx, referenced.ID); !errors.Is(err, errors.Validation) {
		t.Fatalf("group reference ignored: %v", err)
	}
}

func TestRoleNameCapabilityEnforcesCompleteCatalogAndLifetime(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	a := env.roleService.crudApplication
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write")
	var retained *roleCRUDAccess
	command, err := app.NewCommand(app.CommandOptions[roleCRUDInput, *roleCRUDAccess, struct{}]{Resources: a.resources["create"],
		Access: func(_ context.Context, in roleCRUDInput, grants []*app.CommandGrant) (*roleCRUDAccess, error) {
			var e error
			retained, e = a.bind("create", in, grants)
			return retained, e
		},
		Handler: func(context.Context, roleCRUDInput, *roleCRUDAccess) (struct{}, error) { return struct{}{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = command.Execute(ctx, roleCRUDInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err = retained.names.Read(ctx, roleNameQuery{}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained capability: %v", err)
	}
	copyApp := *a
	copyApp.resources = map[string][]app.CommandResource[roleCRUDInput]{"create": append([]app.CommandResource[roleCRUDInput](nil), a.resources["create"]...)}
	d := copyApp.resources["create"][1]
	plan, _ := d.Authorizer.Plan()
	d.Authorizer, err = auth.Compile(auth.Declaration{Descriptor: plan.Descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{Constraints: []auth.IPolicy{auth.PolicyFunc(func(context.Context, auth.Request) (auth.Decision, error) {
		return auth.Decision{Allowed: true, Spec: spec.Spec{}}, nil
	})}}}}, auth.CompileOptions{Checker: auth.ActionCheckerFunc(func(context.Context, string) error { return nil }), Metadata: d.Repository.ExecutionDescriptor().Metadata()})
	if err != nil {
		t.Fatal(err)
	}
	copyApp.resources["create"][1] = d
	_, err = copyApp.execute(ctx, "create", nil, func(ctx context.Context, core *appcrud.Application[*iamentity.Role, int64], _ *roleCRUDAccess) (*iamentity.Role, error) {
		item := &iamentity.Role{Name: "cannot-skip-directory", Permissions: iamentity.PermissionArray{"role:api:read"}}
		return item, core.Create(ctx, item)
	})
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("filtered invariant catalog accepted: %v", err)
	}
}

func TestRoleGroupCommandsKeepIndependentScopesAndPlatformOwnership(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	role := env.createTestRole(t, "group-role")
	group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Name: "group"}
	if err := env.db.Create(group).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write", "role:api:read")
	if err := env.roleService.AssignRoleToGroup(ctx, role.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(group).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.roleService.RemoveRoleFromGroup(ctx, role.ID, group.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("out-of-scope group removal: %v", err)
	}
	groups, err := env.roleService.RoleGroups(ctx, role.ID)
	if err != nil || len(groups) != 0 {
		t.Fatalf("group directory escaped its independent scope: %+v %v", groups, err)
	}
	var count int64
	if err := env.db.Table("group_roles").Where("role_id = ? AND group_id = ?", role.ID, group.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("denied removal changed links: count=%d error=%v", count, err)
	}
	if err := env.db.Model(role).Update("owner_id", "platform").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := env.roleService.UpdateRole(ctx, role.ID, &svc.UpdateRoleRequest{Name: "forbidden"}); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("platform ownership guard: %v", err)
	}
}
