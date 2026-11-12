package user_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	usersvc "gochen-iam/service/user"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func userAssociationPrincipal(t *testing.T, tenantID, subject, kind string, permissions ...string) context.Context {
	t.Helper()
	ctx, err := contextx.WithTenantID(t.Context(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: subject, ActiveScopeID: 1, Permissions: permissions})
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

func TestUserAssociationReadsRejectBeforeAllQueries(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	queries := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:association:queries", func(*gorm.DB) { queries.Add(1) }); err != nil {
		t.Fatal(err)
	}
	untrusted, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(untrusted, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{untrusted, trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")} {
		if _, err := env.userService.UserRoles(ctx, 1); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("roles denial=%v", err)
		}
		if _, err := env.userService.UserGroups(ctx, 1); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("groups denial=%v", err)
		}
	}
	for _, action := range []string{"roles", "groups"} {
		for _, test := range []struct {
			ctx  context.Context
			code errors.ErrorCode
		}{
			{userAssociationPrincipal(t, env.tenantID, "7", "tenant", "user:api:read"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:read", "user:api:manage"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "trace", "platform", "user:api:read", "user:api:manage"), errors.Unauthorized},
		} {
			if _, err := env.userService.ExecuteAssociationReadHTTP(test.ctx, action, usersvc.UserAssociationReadInput{ID: 1}); !errors.Is(err, test.code) {
				t.Fatalf("HTTP %s denial=%v, want %s", action, err, test.code)
			}
		}
		if _, err := env.userService.ExecuteAssociationReadHTTP(nil, action, usersvc.UserAssociationReadInput{ID: 1}); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("nil context=%v", err)
		}
		if _, err := env.userService.ExecuteAssociationReadHTTP(untrusted, action, usersvc.UserAssociationReadInput{ID: 0}); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("invalid ID=%v", err)
		}
	}
	if queries.Load() != 0 {
		t.Fatalf("rejected association reads issued %d queries", queries.Load())
	}
}

func TestUserAssociationReadsFilterAllNestedResources(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	visible := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "inside", Username: "target", Email: "target@example.test", Status: "active"}
	visible.ID = 99
	if err := env.db.Create(visible).Error; err != nil {
		t.Fatal(err)
	}
	parent := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: "inside", Name: "parent", Level: 1}
	parent.ID = 90
	if err := env.db.Create(parent).Error; err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"visible", "hidden", "foreign", "deleted", "inactive-binding"} {
		id, scopeID, tenantID := int64(i+100), int64(1), env.tenantID
		var deletedAt *time.Time
		bindingStatus := "active"
		switch name {
		case "hidden":
			scopeID = 2
		case "foreign":
			tenantID = "other"
		case "deleted":
			now := time.Now()
			deletedAt = &now
		case "inactive-binding":
			bindingStatus = "inactive"
		}
		group := &iamentity.Group{TenantID: tenantID, ManagedScopeID: scopeID, OwnerID: "owner", Name: name, ParentID: &parent.ID, Level: 2, DeletedAt: deletedAt}
		group.ID = id
		user := &iamentity.User{TenantID: tenantID, ManagedScopeID: scopeID, HomeTenantID: tenantID, HomeScopeID: scopeID, OwnerID: "owner", Username: name, Email: name + "@example.test", Status: "active", DeletedAt: deletedAt}
		user.ID = id
		role := &iamentity.Role{TenantID: tenantID, NamespaceScopeID: scopeID, OwnerID: "owner", Name: name, DeletedAt: deletedAt}
		role.ID = id
		for _, item := range []any{group, user, role, &iamentity.UserRoleBinding{UserID: visible.ID, RoleID: id, GrantScopeID: 1, Status: bindingStatus}} {
			if err := env.db.Create(item).Error; err != nil {
				t.Fatal(err)
			}
		}
		if name != "inactive-binding" {
			if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", visible.ID, id).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, 100)", id).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.db.Exec("INSERT INTO group_roles (group_id, role_id) VALUES (100, ?)", id).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:association:no-preloads", func(tx *gorm.DB) {
		if len(tx.Statement.Preloads) != 0 {
			tx.AddError(fmt.Errorf("association query used undeclared preloads"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:manage")
	for _, http := range []bool{false, true} {
		var roles []*iamentity.Role
		var groups []*iamentity.Group
		var err error
		if http {
			out, readErr := env.userService.ExecuteAssociationReadHTTP(ctx, "roles", usersvc.UserAssociationReadInput{ID: visible.ID})
			roles, err = out.Roles, readErr
		} else {
			roles, err = env.userService.UserRoles(ctx, visible.ID)
		}
		if err != nil || len(roles) != 1 || roles[0].ID != 100 || roles[0].NamespaceScope == nil || roles[0].NamespaceScope.ID != 1 {
			t.Fatalf("HTTP=%v roles=%+v error=%v", http, roles, err)
		}
		if http {
			out, readErr := env.userService.ExecuteAssociationReadHTTP(ctx, "groups", usersvc.UserAssociationReadInput{ID: visible.ID})
			groups, err = out.Groups, readErr
		} else {
			groups, err = env.userService.UserGroups(ctx, visible.ID)
		}
		if err != nil || len(groups) != 1 || groups[0].ID != 100 {
			t.Fatalf("HTTP=%v groups=%+v error=%v", http, groups, err)
		}
		group := groups[0]
		if group.Parent == nil || group.Parent.ID != parent.ID || len(group.Users) != 3 || len(group.DefaultRoles) != 2 {
			t.Fatalf("HTTP=%v nested group=%+v", http, group)
		}
		for _, user := range group.Users {
			if user.ManagedScopeID != 1 || user.TenantID != env.tenantID || user.DeletedAt != nil {
				t.Fatalf("leaked member=%+v", user)
			}
		}
	}
	// A parent outside the group condition retains ParentID but reveals no entity.
	if err := env.db.Model(parent).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	groups, err := env.userService.UserGroups(ctx, visible.ID)
	if err != nil || len(groups) != 1 || groups[0].Parent != nil || groups[0].ParentID == nil || *groups[0].ParentID != parent.ID {
		t.Fatalf("hidden parent=%+v error=%v", groups, err)
	}
	if err := env.db.Model(&iamentity.Scope{}).Where("id = 1").Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	roles, err := env.userService.UserRoles(ctx, visible.ID)
	if err != nil || len(roles) != 1 || roles[0].NamespaceScope != nil {
		t.Fatalf("deleted namespace=%+v error=%v", roles, err)
	}
	// Reject the primary user before entering any association table.
	if err := env.db.Model(visible).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	associationReads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:association:primary", func(tx *gorm.DB) {
		if tx.Statement.Table != "users" {
			associationReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.userService.UserRoles(ctx, visible.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("hidden primary roles=%v", err)
	}
	if _, err := env.userService.UserGroups(ctx, visible.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("hidden primary groups=%v", err)
	}
	if associationReads.Load() != 0 {
		t.Fatalf("hidden primary issued %d association reads", associationReads.Load())
	}
}

func TestUserAssociationReadsReturnAllPages(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	groups := make([]*iamentity.Group, 1001)
	roles := make([]*iamentity.Role, 1001)
	bindings := make([]*iamentity.UserRoleBinding, 1001)
	for i := range groups {
		id := int64(i + 100)
		groups[i] = &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: "owner", Name: fmt.Sprintf("group-%d", id), Level: 1}
		groups[i].ID = id
		roles[i] = &iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: 1, OwnerID: "owner", Name: fmt.Sprintf("role-%d", id)}
		roles[i].ID = id
		bindings[i] = &iamentity.UserRoleBinding{UserID: user.ID, RoleID: id, GrantScopeID: 1, Status: "active"}
	}
	for _, items := range []any{groups, roles, bindings} {
		if err := env.db.CreateInBatches(items, 100).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) SELECT 99, id FROM groups").Error; err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")
	foundGroups, err := env.userService.UserGroups(ctx, user.ID)
	if err != nil || len(foundGroups) != 1001 || len(foundGroups[1000].Users) != 1 || foundGroups[1000].Users[0].ID != user.ID {
		t.Fatalf("groups count=%d error=%v", len(foundGroups), err)
	}
	foundRoles, err := env.userService.UserRoles(ctx, user.ID)
	if err != nil || len(foundRoles) != 1001 || foundRoles[1000].NamespaceScope == nil || foundRoles[1000].NamespaceScope.ID != 1 {
		t.Fatalf("roles count=%d error=%v", len(foundRoles), err)
	}
}

func TestUserAssociationReadsPreserveSingleTenantAndSystem(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, ManagedScopeID: 1, HomeScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	ctx := iamtenant.WithPolicy(userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:read", "user:api:manage"), iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
	for _, action := range []string{"roles", "groups"} {
		if _, err := env.userService.ExecuteAssociationReadHTTP(ctx, action, usersvc.UserAssociationReadInput{ID: user.ID}); err != nil {
			t.Fatalf("single %s=%v", action, err)
		}
		if _, err := env.userService.ExecuteAssociationReadHTTP(env.backgroundCtx, action, usersvc.UserAssociationReadInput{ID: user.ID}); err != nil {
			t.Fatalf("System %s=%v", action, err)
		}
		binding, err := env.userService.AssociationReadAuthorizationBinding(action)
		if err != nil {
			t.Fatal(err)
		}
		binding.Entry = auth.Entry{Kind: "service", Key: "user." + action}
		if _, err := auth.ValidateEntries([]auth.Entry{binding.Entry}, []auth.EntryBinding{binding}); err != nil {
			t.Fatal(err)
		}
		want := map[string]int{"roles": 2, "groups": 3}[action]
		if len(binding.Resources) != want {
			t.Fatalf("%s missing nested plans=%+v", action, binding)
		}
	}
}
