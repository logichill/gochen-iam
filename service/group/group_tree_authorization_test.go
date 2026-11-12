package group_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestGroupTreeRejectsBeforeResourceReads(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	for _, ctx := range []context.Context{t.Context(), associationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		if _, err := env.groupService.GroupTree(ctx); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("tree denial=%v", err)
		}
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "tenant", "group:api:read")
	if _, err := env.groupService.GroupTreeHTTP(ctx); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("HTTP tree entry denial=%v", err)
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("tree denial reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupTreeCountsOnlyAuthorizedMembersAndPreservesHierarchy(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root := createAssociationGroup(t, env)
	rootID := root.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "child", ParentID: &rootID})
	if err != nil {
		t.Fatal(err)
	}
	u1 := env.createTestUser(t, "visible", "visible@example.com")
	u2 := env.createTestUser(t, "hidden", "hidden@example.com")
	u3 := env.createTestUser(t, "other", "other@example.com")
	u4 := env.createTestUser(t, "deleted", "deleted@example.com")
	for _, pair := range [][2]int64{{root.GetID(), u1.GetID()}, {root.GetID(), u2.GetID()}, {child.GetID(), u1.GetID()}, {child.GetID(), u3.GetID()}, {root.GetID(), u4.GetID()}} {
		if err := env.groupService.AddUserToGroup(env.backgroundCtx, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.db.Model(u2).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(u3).Update("tenant_id", "other").Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(u4).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Query().Before("gorm:query").Register("tree:test:no-preloads", func(tx *gorm.DB) {
		if tx.Statement.Table != "groups" && tx.Statement.Table != "users" {
			tx.AddError(errors.NewCode(errors.Internal, "tree read an undeclared resource"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read", "group:api:manage")
	for _, invoke := range []func(context.Context) ([]*svc.GroupTreeNode, error){env.groupService.GroupTree, env.groupService.GroupTreeHTTP} {
		tree, err := invoke(ctx)
		if err != nil || len(tree) != 1 || tree[0].ID != rootID || tree[0].UserCount != 1 || len(tree[0].Children) != 1 ||
			tree[0].Children[0].ID != child.GetID() || tree[0].Children[0].Level != 2 || tree[0].Children[0].UserCount != 1 {
			t.Fatalf("authorized tree=%+v error=%v", tree, err)
		}
	}
	tree, err := env.groupService.GroupTree(env.backgroundCtx)
	if err != nil || len(tree) != 1 || tree[0].UserCount != 2 || tree[0].Children[0].UserCount != 1 {
		t.Fatalf("system tenant tree=%+v error=%v", tree, err)
	}
}

func TestGroupTreeReturnsAllPages(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	groups := make([]*iamentity.Group, 1001)
	for i := range groups {
		groups[i] = &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Name: fmt.Sprintf("root-%04d", i), Level: 1, Path: fmt.Sprintf("/%d", i+1)}
		groups[i].SetID(int64(i + 1))
	}
	if err := env.db.CreateInBatches(groups, 100).Error; err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")
	tree, err := env.groupService.GroupTree(ctx)
	if err != nil || len(tree) != len(groups) || tree[0].Name != "root-0000" || tree[len(tree)-1].Name != "root-1000" {
		t.Fatalf("tree pages count=%d error=%v", len(tree), err)
	}
}
