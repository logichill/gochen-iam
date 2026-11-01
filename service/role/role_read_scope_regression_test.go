package role

import (
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	"gochen/auth/scoped"
)

func TestRoleReadQueriesUseConsistentDataScope(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})
	visibleRole := env.createTestRole(t, "visible-role")
	invisibleRole := &iamentity.Role{TenantID: env.tenantID, OwnerID: svc.TenantOwnerID(env.tenantID), NamespaceScopeID: 2, Code: "hidden-role", Name: "hidden-role", Status: svc.RoleStatusActive, IsSystem: true}
	if err := env.db.Create(invisibleRole).Error; err != nil {
		t.Fatal(err)
	}
	for index, scopeID := range []int64{1, 2} {
		username := []string{"visible-user", "hidden-user"}[index]
		user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: scopeID, ManagedScopeID: scopeID, OwnerID: svc.TenantOwnerID(env.tenantID), Username: username, Email: username + "@example.com", Status: svc.UserStatusActive}
		if err := env.db.Create(user).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: user.ID, RoleID: visibleRole.ID, GrantScopeID: scopeID, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name                 string
		scope                scoped.DataScope
		users, total, system int64
	}{
		{"filtered", scoped.Filtered(1), 1, 1, 0},
		{"global", scoped.Global(), 2, 2, 1},
		{"deny_all", scoped.DenyAll(), 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := iamauth.BindActiveScopeContext(env.backgroundCtx, 1, string(iammw.ScopeTenant))
			ctx, err := auth.WithPrincipal(ctx, auth.Principal{SubjectID: "42", Permissions: []string{svc.RolePermissionSet.Code(iammw.ActionRead)}, ActiveScopeID: 1})
			if err != nil {
				t.Fatal(err)
			}
			ctx, err = scoped.WithDataScope(ctx, tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			users, err := env.roleService.RoleUsers(ctx, visibleRole.ID)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(users)) != tc.users {
				t.Fatalf("users=%d, want %d", len(users), tc.users)
			}
			if tc.name == "filtered" && users[0].ManagedScopeID != 1 {
				t.Fatal("out-of-scope user leaked")
			}
			stats, err := env.roleService.RoleStatistics(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if stats["total_roles"] != tc.total || stats["active_roles"] != int(tc.total) || stats["system_roles"] != int(tc.system) {
				t.Fatalf("statistics use different scopes: %v", stats)
			}
			counts := stats["roles_by_status"].(map[string]int64)
			if counts[svc.RoleStatusActive] != tc.total {
				t.Fatalf("status count=%v, want %d", counts, tc.total)
			}
		})
	}
}
