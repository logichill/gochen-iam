package menu

import (
	"context"
	"testing"

	"gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen/domain/crud"
	hbasic "gochen/httpx/nethttp"
)

func TestBuildMenuTree_NoContext_ShowsOnlyUnrestricted(t *testing.T) {
	items := []*iamentity.MenuItem{
		{Entity: crud.Entity[int64]{ID: 1}, Code: "root", Title: "Root", Published: true},
		{Entity: crud.Entity[int64]{ID: 2}, Code: "secure", Title: "Secure", Published: true, AllOfPermissions: iamentity.StringArray{"a:b"}},
	}

	tree := buildMenuTree(items, nil)
	if len(tree) != 1 {
		t.Fatalf("expected 1 root, got %d", len(tree))
	}
	if tree[0].Code != "root" {
		t.Fatalf("expected root to be visible, got %s", tree[0].Code)
	}
}

func TestBuildMenuTree_WithPermissions_AnyAllAndParentRetention(t *testing.T) {
	rootID := int64(10)
	childID := int64(11)

	items := []*iamentity.MenuItem{
		{
			Entity:           crud.Entity[int64]{ID: rootID},
			Code:             "root",
			Title:            "Root",
			Published:        true,
			AllOfPermissions: iamentity.StringArray{"x:y"}, // user does not have
		},
		{
			Entity:    crud.Entity[int64]{ID: childID},
			Code:      "child",
			ParentID:  &rootID,
			Title:     "Child",
			Published: true,
			AnyOfPermissions: iamentity.StringArray{
				"a:b", // user has
				"c:d",
			},
		},
	}

	reqCtx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	reqCtx = hbasic.WithUserID(reqCtx, 1)
	reqCtx = auth.WithRoles(reqCtx, []string{"user"})
	reqCtx = auth.WithPermissions(reqCtx, []string{"a:b"})

	tree := buildMenuTree(items, reqCtx)
	if len(tree) != 1 {
		t.Fatalf("expected 1 root, got %d", len(tree))
	}
	if tree[0].Code != "root" {
		t.Fatalf("expected root code=root, got %s", tree[0].Code)
	}
	if len(tree[0].Children) != 1 || tree[0].Children[0].Code != "child" {
		t.Fatalf("expected child to be visible under root")
	}
}

func TestBuildMenuTree_TenantOverride_AppliesAndFilters(t *testing.T) {
	items := []*iamentity.MenuItem{
		{Entity: crud.Entity[int64]{ID: 1}, Code: "root", Title: "Root", Published: true},
	}

	reqCtx, err := hbasic.NewRequestContext(context.Background())
	if err != nil {
		t.Fatalf("NewRequestContext: %v", err)
	}
	reqCtx = hbasic.WithUserID(reqCtx, 1)
	reqCtx = auth.WithRoles(reqCtx, []string{"user"})

	tree := buildMenuTree(items, reqCtx)
	if len(tree) != 1 || tree[0].Code != "root" {
		t.Fatalf("expected root to be visible, got %#v", tree)
	}
}

func TestSortMenuTree_OrderThenTitle(t *testing.T) {
	items := []*iamentity.MenuItem{
		{Entity: crud.Entity[int64]{ID: 1}, Code: "b", Title: "B", Order: 2, Published: true},
		{Entity: crud.Entity[int64]{ID: 2}, Code: "a", Title: "A", Order: 1, Published: true},
	}
	tree := buildMenuTree(items, nil)
	if len(tree) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(tree))
	}
	if tree[0].Code != "a" || tree[1].Code != "b" {
		t.Fatalf("expected order a then b, got %s then %s", tree[0].Code, tree[1].Code)
	}
}

func TestSortAndFilterMenuTree_CycleDoesNotStackOverflow(t *testing.T) {
	// 构造一个人为的 children 环，确保 sort/filter 的递归防御有效。
	a := &MenuNode{ID: 1, Code: "a", Title: "A", Order: 1}
	b := &MenuNode{ID: 2, Code: "b", Title: "B", Order: 2}
	a.Children = []*MenuNode{b}
	b.Children = []*MenuNode{a}

	sortMenuTree([]*MenuNode{a})
	_ = filterMenuTree([]*MenuNode{a}, nil)
}
