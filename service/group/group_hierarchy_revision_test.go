package group_test

import (
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestGroupRepoMoveEditedSubtreeUsesCurrentRevisions(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	a, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "revision-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "revision-b"})
	if err != nil {
		t.Fatal(err)
	}
	aid := a.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "revision-child", ParentID: &aid})
	if err != nil {
		t.Fatal(err)
	}
	// 种入已编辑节点的非零版本；层级修复须使用当前版本并在成功写入后推进。
	childVersion := uint64(3)
	if err := env.db.Model(child).Updates(map[string]any{"name": "edited-child", "version": childVersion}).Error; err != nil {
		t.Fatal(err)
	}
	bid := b.GetID()
	for _, parent := range []*int64{&bid, nil} {
		a.Parent = nil
		a.ParentID = parent
		if err := env.groupRepo.Update(env.backgroundCtx, a, spec.All()); err != nil {
			t.Fatalf("move parent with edited descendant: %v", err)
		}
		childVersion++
		child, err = env.groupRepo.Get(env.backgroundCtx, child.GetID(), spec.All())
		if err != nil {
			t.Fatal(err)
		}
		if child.GetVersion() != childVersion || child.Name != "edited-child" || child.Path != a.Path+"/"+strconv.FormatInt(child.GetID(), 10) {
			t.Fatalf("unexpected child hierarchy or revision: %v, version=%d, want version=%d", child, child.GetVersion(), childVersion)
		}
	}
}

func TestUpdateGroup_RejectsMovingSubtreeExceedingMaxLevel(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)

	// Build chain: g1 -> g2 -> ... -> g8 (level 8)
	var prevID *int64
	for i := 1; i <= 8; i++ {
		g, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
			TenantID: env.tenantID,
			Name:     "chain-" + strconv.Itoa(i),
			ParentID: prevID,
		})
		if err != nil {
			t.Fatalf("create chain-%d: %v", i, err)
		}
		id := g.GetID()
		prevID = &id
	}
	g8ID := *prevID

	// Build branch: b1 -> b2 -> b3 -> b4 (depth 4: b1 level 1, b4 level 4)
	var branchPrev *int64
	var b1ID int64
	for i := 1; i <= 4; i++ {
		g, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
			TenantID: env.tenantID,
			Name:     "branch-" + strconv.Itoa(i),
			ParentID: branchPrev,
		})
		if err != nil {
			t.Fatalf("create branch-%d: %v", i, err)
		}
		id := g.GetID()
		if i == 1 {
			b1ID = id
		}
		branchPrev = &id
	}

	// Moving b1 under g8 would make b1 level 9, b4 level 12 > 10.
	_, err := env.groupService.UpdateGroup(
		env.backgroundCtx,
		b1ID,
		&svc.UpdateGroupRequest{},
		svc.ValueFieldPatch(func(group *iamentity.Group, parentID *int64) {
			group.ParentID = parentID
		}, &g8ID),
	)
	if err == nil {
		t.Fatal("expected error when moving subtree would exceed max group level (10), got nil")
	}
	if !errors.Is(err, errors.Validation) {
		t.Fatalf("expected Validation error, got %v", err)
	}
}
