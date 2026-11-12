package user_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	usersvc "gochen-iam/service/user"
	hostauthz "gochen-runtime/host/authz"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gochen/observe/logging"
	"gorm.io/gorm"
)

func TestUserDirectoryRejectsBeforeBusinessOrFactQueries(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	reads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:directory:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(base, "7")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := hostauthz.WithPrincipal(base, hostauthz.Principal{SubjectID: "7", ActiveScopeID: env.rootScopeID, Permissions: []string{"user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{{nil, errors.InvalidInput}, {base, errors.Unauthorized}, {trace, errors.Unauthorized}, {wrong, errors.Forbidden}} {
		if _, err := env.userService.SearchUsers(test.ctx, "target", 10); !errors.Is(err, test.code) {
			t.Fatalf("search=%v, want %s", err, test.code)
		}
		if _, err := env.userService.UsersByStatus(test.ctx, "active"); !errors.Is(err, test.code) {
			t.Fatalf("status=%v, want %s", err, test.code)
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("rejected directories read %d queries", reads.Load())
	}
}

func TestUserDirectoryFiltersPrimaryAndAssociationsBeforeLimit(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	now := time.Now()
	users := []iamentity.User{
		{TenantID: env.tenantID, HomeTenantID: env.tenantID, ManagedScopeID: env.rootScopeID + 100, OwnerID: "outside", Username: "target-outside", Email: "outside@example.test", Status: "active"},
		{TenantID: env.tenantID, HomeTenantID: env.tenantID, ManagedScopeID: env.rootScopeID, OwnerID: "inside", Username: "target-inside", Email: "inside@example.test", Status: "active"},
		{TenantID: "other", HomeTenantID: "other", ManagedScopeID: env.rootScopeID, OwnerID: "other", Username: "target-other", Email: "other@example.test", Status: "active"},
		{TenantID: env.tenantID, HomeTenantID: env.tenantID, ManagedScopeID: env.rootScopeID, OwnerID: "deleted", Username: "target-deleted", Email: "deleted@example.test", Status: "active", DeletedAt: &now},
	}
	for i := range users {
		users[i].ID = int64(100 + i)
	}
	if err := env.db.Create(&users).Error; err != nil {
		t.Fatal(err)
	}
	groups := []iamentity.Group{
		{TenantID: env.tenantID, Name: "Visible", ManagedScopeID: env.rootScopeID, OwnerID: "inside"},
		{TenantID: env.tenantID, Name: "Hidden", ManagedScopeID: env.rootScopeID + 100, OwnerID: "outside"},
	}
	roles := []iamentity.Role{
		{TenantID: env.tenantID, Name: "Visible", NamespaceScopeID: env.rootScopeID, OwnerID: "inside"},
		{TenantID: env.tenantID, Name: "Hidden", NamespaceScopeID: env.rootScopeID + 100, OwnerID: "outside"},
	}
	for i := range groups {
		groups[i].ID = int64(100 + i)
		roles[i].ID = int64(100 + i)
	}
	if err := env.db.Create(&groups).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&roles).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{100, 101} {
		if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", 101, id).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: 101, RoleID: id, GrantScopeID: env.rootScopeID, Status: "active", CreatedAt: now, UpdatedAt: now}).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: env.rootScopeID, Permissions: []string{"user:api:read"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, env.rootScopeID, iamentity.ScopeTypeTenant)
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(env.rootScopeID))
	if err != nil {
		t.Fatal(err)
	}
	factReads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:directory:coverage", func(tx *gorm.DB) {
		if tx.Statement.Table == "scope_visibility_map" {
			factReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"search", "by_status"} {
		before := factReads.Load()
		var found []*iamentity.User
		if action == "search" {
			found, err = env.userService.SearchUsers(ctx, "target", 1)
		} else {
			found, err = env.userService.UsersByStatus(ctx, "active")
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].ID != 101 {
			t.Fatalf("%s ignored primary filter/limit: %+v", action, found)
		}
		if len(found[0].Groups) != 1 || found[0].Groups[0].ID != 100 || len(found[0].Roles) != 1 || found[0].Roles[0].ID != 100 {
			t.Fatalf("%s leaked associations: %+v", action, found[0])
		}
		if factReads.Load()-before != 1 {
			t.Fatalf("%s coverage reads=%d, want one across three resources", action, factReads.Load()-before)
		}
	}
	for _, action := range []string{"search", "by_status"} {
		binding, err := env.userService.AuthorizationBinding(action)
		if err != nil {
			t.Fatal(err)
		}
		binding.Entry = auth.Entry{Kind: "service", Key: "user." + action}
		if _, err := auth.ValidateEntries([]auth.Entry{binding.Entry}, []auth.EntryBinding{binding}); err != nil {
			t.Fatal(err)
		}
		if len(binding.Resources) != 2 {
			t.Fatalf("%s lacks association resources", action)
		}
	}
}

func TestUserDirectorySystemStillRequiresTenantRootCoverage(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	outside := &iamentity.Scope{Key: "outside", Name: "Outside", Type: "region", Path: "/outside/", Status: "active"}
	outside.ID = 100
	if err := env.db.Create(outside).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.scopeRepo.RebuildVisibilityMap(env.backgroundCtx); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", IsSystem: true, ActiveScopeID: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 100, "region")
	if _, err := env.userService.SearchUsers(ctx, "", 10); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("system outside root=%v", err)
	}
	if _, err := env.userService.UsersByStatus(ctx, "active"); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("system status outside root=%v", err)
	}
}

func TestUserDirectoryConstructorRequiresActualProviders(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	for _, construct := range []func() error{
		func() error {
			_, err := usersvc.NewUserService(nil, env.groupRepo, env.roleRepo, nil, svc.NewIAMAccess(nil), logging.NewNoopLogger())
			return err
		},
		func() error {
			_, err := usersvc.NewUserService(env.userRepo, nil, env.roleRepo, nil, svc.NewIAMAccess(nil), logging.NewNoopLogger())
			return err
		},
		func() error {
			_, err := usersvc.NewUserService(env.userRepo, env.groupRepo, nil, nil, svc.NewIAMAccess(nil), logging.NewNoopLogger())
			return err
		},
		func() error {
			_, err := usersvc.NewUserService(env.userRepo, env.groupRepo, env.roleRepo, nil, nil, logging.NewNoopLogger())
			return err
		},
	} {
		if err := construct(); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("missing provider=%v", err)
		}
	}
}
