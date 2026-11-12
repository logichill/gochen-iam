package role

import (
	"context"
	"strings"
	"testing"

	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/crud"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/gen"
	"gochen/observe/logging"
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestRoleDirectoriesRetainTenantCatalogAndActualRelations(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	visible := env.createTestRole(t, "catalog-visible")
	hidden := env.createTestRole(t, "catalog-hidden")
	if err := env.db.Model(hidden).Update("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	other := &iamentity.Role{TenantID: "other", OwnerID: "tenant:other", NamespaceScopeID: 2, Name: "catalog-other", Code: "catalog-other", Status: "active"}
	if err := env.db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 2, ManagedScopeID: 2, OwnerID: svc.TenantOwnerID(env.tenantID), Username: "catalog-user", Email: "catalog@example.com", Status: "active"}
	group := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 2, OwnerID: svc.TenantOwnerID(env.tenantID), Name: "catalog-group"}
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(group).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: hidden.ID, GrantScopeID: 2, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec("INSERT INTO group_roles (group_id,role_id) VALUES (?,?)", group.ID, hidden.ID).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:read", "role:api:manage")
	for _, read := range []func() ([]*iamentity.Role, error){func() ([]*iamentity.Role, error) { return env.roleService.SearchRoles(ctx, "catalog-", 10) }, func() ([]*iamentity.Role, error) { return env.roleService.ActiveRoles(ctx) }} {
		items, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 2 {
			t.Fatalf("tenant catalog=%+v", items)
		}
		for _, item := range items {
			if item.ID == hidden.ID {
				if len(item.Users) != 1 || item.Users[0].ID != user.ID || len(item.Groups) != 1 || item.Groups[0].ID != group.ID {
					t.Fatalf("actual relations missing: %+v", item)
				}
			} else if item.ID != visible.ID || len(item.Users) != 0 || len(item.Groups) != 0 {
				t.Fatalf("unrelated projection: %+v", item)
			}
		}
	}
	items, err := env.roleService.HTTPApplication().List(ctx, 0, 10)
	if err != nil || len(items) != 1 || items[0].ID != visible.ID {
		t.Fatalf("CRUD list scope: %+v %v", items, err)
	}
	for _, action := range []string{"search", "active"} {
		binding, err := env.roleService.directoryCommands[action].AuthorizationBinding()
		if err != nil || len(binding.Resources) != 3 {
			t.Fatalf("directory capabilities=%+v %v", binding, err)
		}
	}
}

func TestRoleCRUDOnePrimaryDecisionAndOneTransactionRead(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	item := env.createTestRole(t, "once")
	item.Permissions = iamentity.PermissionArray{"role:api:read"}
	if err := env.db.Model(item).Update("permissions", item.Permissions).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write")
	a := *env.roleService.crudApplication
	a.resources = map[string][]app.CommandResource[roleCRUDInput]{"update": append([]app.CommandResource[roleCRUDInput](nil), a.resources["update"]...)}
	plan, _ := a.resources["update"][0].Authorizer.Plan()
	decisions := 0
	compiled, err := auth.Compile(auth.Declaration{Descriptor: plan.Descriptor, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{Constraints: []auth.IPolicy{auth.PolicyFunc(func(context.Context, auth.Request) (auth.Decision, error) {
		decisions++
		return auth.Decision{Allowed: true, Spec: spec.All()}, nil
	})}}}}, auth.CompileOptions{Metadata: env.roleRepo.ExecutionDescriptor().Metadata(), Checker: auth.ActionCheckerFunc(func(context.Context, string) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	a.options.Authorizer = compiled
	a.resources["update"][0].Authorizer = compiled
	reads := 0
	if err := env.db.Callback().Query().After("gorm:query").Register("role-completion:reads", func(db *gorm.DB) {
		if db.Statement.Table == "roles" && !strings.Contains(strings.ToLower(db.Statement.SQL.String()), "count(") {
			reads++
		}
	}); err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(ctx, "update", item.ID, func(_ context.Context, r *iamentity.Role) error { r.Description = "changed"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if decisions != 1 || reads != 1 || result.Version != item.Version+1 {
		t.Fatalf("decisions=%d reads=%d result=%+v", decisions, reads, result)
	}
	stale := *item
	stale.Name = "stale"
	if err := a.Update(ctx, &stale); !errors.Is(err, errors.Concurrency) {
		t.Fatalf("stale update=%v", err)
	}
}

func roleServiceWithTenantRoot(t *testing.T, env *roleBulkTestEnv) *RoleService {
	t.Helper()
	if err := env.db.AutoMigrate(&iamentity.Tenant{}); err != nil {
		t.Fatal(err)
	}
	rootID := int64(1)
	if err := env.db.Create(&iamentity.Scope{Entity: crud.Entity[int64]{ID: rootID}, Key: "tenant:" + env.tenantID, Name: "tenant", Type: "tenant", Path: "/tenant/", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&iamentity.Tenant{Key: env.tenantID, Name: "tenant", RootScopeID: &rootID, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&iamentity.ScopeVisibility{ViewerScopeID: rootID, TargetScopeID: rootID}).Error; err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(10))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenantrepo.NewTenantRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(10))
	if err != nil {
		t.Fatal(err)
	}
	boundary := svc.NewScopeAuthorizer(scopes, tenants)
	s, err := NewRoleService(env.roleRepo, env.roleService.userRepo, env.roleService.groupRepo, boundary, svc.NewIAMAccess(boundary), nil, gen.NewUUIDGenerator(), logging.NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoleUpdateMissingNamespaceUsesTrustedTenantRootWithoutChangingID(t *testing.T) {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	s := roleServiceWithTenantRoot(t, env)
	item := env.createTestRole(t, "missing-namespace")
	if err := env.db.Model(item).Update("namespace_scope_id", 999).Error; err != nil {
		t.Fatal(err)
	}
	result, err := s.UpdateRole(env.backgroundCtx, item.ID, &svc.UpdateRoleRequest{Name: "restored", Permissions: []string{"role:api:read"}})
	if err != nil || result.NamespaceScopeID != 999 {
		t.Fatalf("missing namespace resolution: %+v %v", result, err)
	}
	if _, err := s.UpdateRole(env.backgroundCtx, item.ID, &svc.UpdateRoleRequest{Permissions: []string{"menu:api:write"}}); !errors.Is(err, errors.Validation) {
		t.Fatalf("trusted tenant boundary=%v", err)
	}
	if err := env.db.Model(&iamentity.Scope{}).Where("id = ?", 1).Update("key", "wrong-root").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateRole(env.backgroundCtx, item.ID, &svc.UpdateRoleRequest{Name: "cannot-write"}); !errors.Is(err, errors.Internal) {
		t.Fatalf("inconsistent root=%v", err)
	}
}

func TestRoleInitializeUsesDeclaredRootAndIsIdempotent(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	s := roleServiceWithTenantRoot(t, env)
	for range 2 {
		if err := s.InitializeSystemRoles(env.backgroundCtx, env.tenantID); err != nil {
			t.Fatal(err)
		}
	}
	var items []*iamentity.Role
	if err := env.db.Find(&items).Error; err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("builtin roles=%+v", items)
	}
	for _, item := range items {
		if !item.IsSystem || item.NamespaceScopeID != 1 || item.TenantID != env.tenantID || item.Name == "system_admin" {
			t.Fatalf("wrong tenant builtin=%+v", item)
		}
	}
	binding, err := s.CustomAuthorizationBinding("initialize")
	if err != nil || len(binding.Resources) != 3 {
		t.Fatalf("initialization capabilities=%+v %v", binding, err)
	}
}

func TestRoleUserCommandsAndPermissionProjectionKeepIndependentConditions(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	role := env.createTestRole(t, "user-role")
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Username: "member", Email: "member@example.com", Status: "active"}
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write", "role:api:read")
	if err := env.roleService.AssignRoleToUser(ctx, role.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	permissions, err := env.roleService.RolePermissions(ctx, role.ID)
	if err != nil || len(permissions) != 1 {
		t.Fatalf("permissions=%v %v", permissions, err)
	}
	permissions[0] = "mutated"
	permissions, err = env.roleService.RolePermissions(ctx, role.ID)
	if err != nil || permissions[0] != "test:api:read" {
		t.Fatalf("permission copy=%v %v", permissions, err)
	}
	if err := env.db.Model(user).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.roleService.RemoveRoleFromUser(ctx, role.ID, user.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("hidden user removal=%v", err)
	}
	if err := env.db.Model(user).Update("managed_scope_id", 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(role).Update("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.roleService.RemoveRoleFromUser(ctx, role.ID, user.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("hidden role removal=%v", err)
	}
	if err := env.db.Model(role).Update("namespace_scope_id", 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.roleService.RemoveRoleFromUser(ctx, role.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := env.db.Model(&iamentity.UserRoleBinding{}).Where("role_id = ? AND user_id = ?", role.ID, user.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("remaining bindings=%d %v", count, err)
	}
	for _, action := range []string{"assign_user", "remove_user"} {
		binding, err := env.roleService.CustomAuthorizationBinding(action)
		if err != nil || len(binding.Resources) != 1 || binding.Resources[0].Name != "user" {
			t.Fatalf("association capabilities=%+v %v", binding, err)
		}
	}
}
