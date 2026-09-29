package role

import (
	"bytes"
	"encoding/json"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	svc "gochen-iam/service"
	"gochen-iam/tenant"
	auth "gochen-runtime/host/authz"
	dbquery "gochen/app/query"
	"gochen/auth/scoped"
	"gochen/errors"
)

func TestRoleRepositoryQueryCountExcludesPlatformScopeFromTenantDataScope(t *testing.T) {
	env := setupRoleBatchTest(t)
	defer env.teardown(t)

	platformRole := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          string(iammw.ScopePlatform),
		NamespaceScopeID: 2,
		Code:             "platform-list-only",
		Name:             "platform-list-only",
		Status:           svc.RoleStatusActive,
	}
	tenantRole := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          svc.TenantOwnerID(env.tenantID),
		NamespaceScopeID: 1,
		Code:             "tenant-list-visible",
		Name:             "tenant-list-visible",
		Status:           svc.RoleStatusActive,
	}
	for _, role := range []*iamentity.Role{platformRole, tenantRole} {
		if err := env.db.Create(role).Error; err != nil {
			t.Fatalf("create role %s: %v", role.Name, err)
		}
	}

	ctx := iamauth.BindActiveScopeContext(env.backgroundCtx, 1, string(iammw.ScopeTenant))
	ctx, err := scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatalf("bind tenant data scope: %v", err)
	}
	count, err := env.roleRepo.QueryCount(ctx, dbquery.QueryOptions{})
	if err != nil {
		t.Fatalf("query tenant role count: %v", err)
	}
	if count != 1 {
		t.Fatalf("tenant role count = %d, want 1 (platform role must stay out of default list scope)", count)
	}
}

func TestRoleServiceRoleUsersRequiresPlatformScopeForPlatformOwnedRole(t *testing.T) {
	env := setupRoleBatchTest(t)
	defer env.teardown(t)
	env.backgroundCtx = tenant.WithPolicy(env.backgroundCtx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})

	const platformScopeID int64 = 2
	role := &iamentity.Role{
		TenantID:         env.tenantID,
		OwnerID:          string(iammw.ScopePlatform),
		NamespaceScopeID: platformScopeID,
		Code:             "platform-admin",
		Name:             "platform-admin",
		Status:           svc.RoleStatusActive,
	}
	if err := env.db.Create(role).Error; err != nil {
		t.Fatalf("create platform-owned role: %v", err)
	}

	user := &iamentity.User{
		TenantID:       env.tenantID,
		HomeTenantID:   env.tenantID,
		HomeScopeID:    platformScopeID,
		ManagedScopeID: platformScopeID,
		OwnerID:        string(iammw.ScopePlatform),
		Username:       "platform-admin",
		Email:          "platform-admin@example.com",
		Password:       "$2a$10$sensitive-password-hash",
		Status:         svc.UserStatusActive,
	}
	if err := env.db.Create(user).Error; err != nil {
		t.Fatalf("create platform-owned user: %v", err)
	}
	if err := env.db.Create(&iamentity.UserRoleBinding{
		UserID:       user.GetID(),
		RoleID:       role.GetID(),
		GrantScopeID: platformScopeID,
		Status:       "active",
	}).Error; err != nil {
		t.Fatalf("create role binding: %v", err)
	}

	tenantCtx := iamauth.BindActiveScopeContext(env.backgroundCtx, 1, string(iammw.ScopeTenant))
	tenantCtx, err := auth.WithPrincipal(tenantCtx, auth.Principal{
		SubjectID:     42,
		Permissions:   []string{svc.RolePermissionSet.Code(iammw.ActionRead)},
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("bind tenant principal: %v", err)
	}
	if _, err := env.roleService.RoleUsers(tenantCtx, role.GetID()); err == nil {
		t.Fatal("expected tenant-scope principal to be rejected")
	} else if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("RoleUsers error = %v, want Forbidden", err)
	}

	platformCtx := iamauth.BindActiveScopeContext(env.backgroundCtx, platformScopeID, string(iammw.ScopePlatform))
	platformCtx, err = auth.WithPrincipal(platformCtx, auth.Principal{
		SubjectID:     7,
		Permissions:   []string{svc.RolePermissionSet.Code(iammw.ActionRead)},
		ActiveScopeID: platformScopeID,
	})
	if err != nil {
		t.Fatalf("bind platform principal: %v", err)
	}
	users, err := env.roleService.RoleUsers(platformCtx, role.GetID())
	if err != nil {
		t.Fatalf("RoleUsers with platform scope: %v", err)
	}
	if len(users) != 1 || users[0].GetID() != user.GetID() {
		t.Fatalf("RoleUsers = %#v, want user %d", users, user.GetID())
	}

	payload, err := json.Marshal(users)
	if err != nil {
		t.Fatalf("marshal RoleUsers response: %v", err)
	}
	if bytes.Contains(payload, []byte(`"password"`)) || bytes.Contains(payload, []byte(user.Password)) {
		t.Fatalf("RoleUsers response leaked password data: %s", payload)
	}
}
