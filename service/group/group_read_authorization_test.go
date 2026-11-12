package group_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestGroupReadRejectsBeforeAnyResourceAccess(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	untrusted, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{untrusted, associationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		for _, invoke := range []func(context.Context) error{
			func(ctx context.Context) error { _, err := env.groupService.RootGroups(ctx, env.tenantID); return err },
			func(ctx context.Context) error { _, err := env.groupService.GroupsByLevel(ctx, 1); return err },
			func(ctx context.Context) error { _, err := env.groupService.GroupUsers(ctx, 1); return err },
			func(ctx context.Context) error { _, err := env.groupService.GroupRoles(ctx, 1); return err },
		} {
			if err := invoke(ctx); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("read denial=%v", err)
			}
		}
	}
	for _, action := range []string{"roots", "by_level", "users", "roles"} {
		ctx := associationPrincipal(t, env.tenantID, "7", "tenant", "group:api:read")
		if _, err := env.groupService.ExecuteReadHTTP(ctx, action, groupsvc.GroupReadInput{ID: 1, Level: 1}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("HTTP %s denial=%v", action, err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("read denial accessed resources: reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupReadFiltersEachResourceAndPreservesAssociations(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root := createAssociationGroup(t, env)
	rootID := root.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "child", ParentID: &rootID})
	if err != nil {
		t.Fatal(err)
	}
	// Every relation includes visible, out-of-scope, cross-tenant and deleted targets.
	for i, visibility := range []string{"visible", "hidden", "foreign", "deleted"} {
		id := int64(i + 10)
		scopeID, tenantID := int64(1), env.tenantID
		var deletedAt *time.Time
		switch visibility {
		case "hidden":
			scopeID = 2
		case "foreign":
			tenantID = "other"
		case "deleted":
			now := time.Now()
			deletedAt = &now
		}
		user := &iamentity.User{TenantID: tenantID, ManagedScopeID: scopeID, HomeTenantID: tenantID, HomeScopeID: scopeID,
			OwnerID: svc.TenantOwnerID(tenantID), Username: visibility, Email: visibility + "@example.com", Status: "active", DeletedAt: deletedAt}
		user.SetID(id)
		role := &iamentity.Role{TenantID: tenantID, NamespaceScopeID: scopeID, OwnerID: svc.TenantOwnerID(tenantID), Name: visibility, DeletedAt: deletedAt}
		role.SetID(id)
		group := &iamentity.Group{TenantID: tenantID, ManagedScopeID: scopeID, OwnerID: svc.TenantOwnerID(tenantID),
			Name: visibility, Level: 2, Path: fmt.Sprintf("/%d/%d", rootID, id), ParentID: &rootID, DeletedAt: deletedAt}
		group.SetID(id)
		for _, item := range []any{user, role, group} {
			if err := env.db.Create(item).Error; err != nil {
				t.Fatal(err)
			}
		}
		for _, sql := range []string{
			"INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
			"INSERT INTO group_roles (role_id, group_id) VALUES (?, ?)",
		} {
			if err := env.db.Exec(sql, id, rootID).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (10, ?)", id).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: 10, RoleID: id, GrantScopeID: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []int64{1, 2} {
		scope := &iamentity.Scope{Key: fmt.Sprintf("scope-%d", id), Name: fmt.Sprintf("namespace-%d", id), Type: "tenant", Path: fmt.Sprintf("/%d/", id)}
		scope.SetID(id)
		if err := env.db.Create(scope).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Callback().Query().Before("gorm:query").Register("group-read:no-preloads", func(tx *gorm.DB) {
		if len(tx.Statement.Preloads) != 0 {
			tx.AddError(errors.NewCode(errors.Internal, "group query used implicit relation reads"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read", "group:api:manage")
	for _, http := range []bool{false, true} {
		read := func(action string, input groupsvc.GroupReadInput) (groupsvc.GroupReadResult, error) {
			if http {
				return env.groupService.ExecuteReadHTTP(ctx, action, input)
			}
			switch action {
			case "roots":
				items, err := env.groupService.RootGroups(ctx, env.tenantID)
				return groupsvc.GroupReadResult{Groups: items}, err
			case "by_level":
				items, err := env.groupService.GroupsByLevel(ctx, input.Level)
				return groupsvc.GroupReadResult{Groups: items}, err
			case "users":
				items, err := env.groupService.GroupUsers(ctx, input.ID)
				return groupsvc.GroupReadResult{Users: items}, err
			default:
				items, err := env.groupService.GroupRoles(ctx, input.ID)
				return groupsvc.GroupReadResult{Roles: items}, err
			}
		}
		out, err := read("roots", groupsvc.GroupReadInput{})
		if err != nil || len(out.Groups) != 1 {
			t.Fatalf("HTTP=%v roots=%+v error=%v", http, out, err)
		}
		g := out.Groups[0]
		if len(g.Children) != 2 || g.Children[0].GetID() != child.GetID() || len(g.Users) != 1 || g.Users[0].Username != "visible" || len(g.DefaultRoles) != 1 || g.DefaultRoles[0].Name != "visible" {
			t.Fatalf("root relations=%+v", g)
		}
		out, err = read("by_level", groupsvc.GroupReadInput{Level: 2})
		if err != nil || len(out.Groups) != 2 || out.Groups[0].Parent == nil || out.Groups[0].Parent.GetID() != rootID {
			t.Fatalf("level relations=%+v error=%v", out, err)
		}
		out, err = read("users", groupsvc.GroupReadInput{ID: rootID})
		if err != nil || len(out.Users) != 1 {
			t.Fatalf("members=%+v error=%v", out, err)
		}
		u := out.Users[0]
		if u.GetID() != 10 || len(u.Groups) != 2 || len(u.Roles) != 1 || u.Roles[0].Name != "visible" {
			t.Fatalf("member relations=%+v", u)
		}
		out, err = read("roles", groupsvc.GroupReadInput{ID: rootID})
		if err != nil || len(out.Roles) != 1 || out.Roles[0].NamespaceScope == nil || out.Roles[0].NamespaceScope.GetID() != 1 {
			t.Fatalf("namespace relations=%+v error=%v", out, err)
		}
	}
	if err := env.db.Model(&iamentity.Scope{}).Where("id = ?", 1).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	roles, err := env.groupService.GroupRoles(ctx, rootID)
	if err != nil || len(roles) != 1 || roles[0].NamespaceScope != nil {
		t.Fatalf("deleted namespace roles=%+v error=%v", roles, err)
	}
}

func TestGroupReadRejectsInvisibleTargetBeforeAssociations(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	if err := env.db.Model(group).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Query().Before("gorm:query").Register("group-read:target-first", func(tx *gorm.DB) {
		if tx.Statement.Table != "groups" {
			tx.AddError(errors.NewCode(errors.Internal, "read associations of an unauthorized group"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")
	if _, err := env.groupService.GroupUsers(ctx, group.GetID()); !errors.Is(err, errors.NotFound) {
		t.Fatalf("members of invisible group=%v", err)
	}
	if _, err := env.groupService.GroupRoles(ctx, group.GetID()); !errors.Is(err, errors.NotFound) {
		t.Fatalf("roles of invisible group=%v", err)
	}
}

func TestGroupReadReturnsAllGroupAndMemberPages(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	groups := make([]*iamentity.Group, 1001)
	users := make([]*iamentity.User, 1001)
	for i := range groups {
		id := int64(i + 1)
		groups[i] = &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Name: fmt.Sprintf("root-%04d", i), Level: 1, Path: fmt.Sprintf("/%d", id)}
		groups[i].SetID(id)
		users[i] = &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, Username: fmt.Sprintf("user-%d", id), Email: fmt.Sprintf("user-%d@example.com", id)}
		users[i].SetID(id)
	}
	for _, items := range []any{groups, users} {
		if err := env.db.CreateInBatches(items, 100).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Exec("INSERT INTO user_groups (user_id, group_id) SELECT id, 1 FROM users").Error; err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")
	roots, err := env.groupService.RootGroups(ctx, env.tenantID)
	if err != nil || len(roots) != 1001 || len(roots[0].Users) != 1001 {
		t.Fatalf("root pages count=%d error=%v", len(roots), err)
	}
	level, err := env.groupService.GroupsByLevel(ctx, 1)
	if err != nil || len(level) != 1001 {
		t.Fatalf("level pages count=%d error=%v", len(level), err)
	}
	members, err := env.groupService.GroupUsers(ctx, 1)
	if err != nil || len(members) != 1001 || len(members[1000].Groups) != 1 {
		t.Fatalf("member pages count=%d error=%v", len(members), err)
	}
}
