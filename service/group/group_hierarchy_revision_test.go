package group_test

import (
	"strconv"
	"testing"

	svc "gochen-iam/service"
	"gochen/auth/scoped"
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
	// 普通 CRUD 实体的时间戳更新不递增版本；显式种入已编辑节点的非零版本。
	const childVersion = uint64(3)
	if err := env.db.Model(child).Updates(map[string]any{"name": "edited-child", "version": childVersion}).Error; err != nil {
		t.Fatal(err)
	}
	bid := b.GetID()
	for _, parent := range []*int64{&bid, nil} {
		a.Parent = nil
		a.ParentID = parent
		ctx := scoped.WithConstraint(env.backgroundCtx, scoped.SingleEntityConstraint(svc.GroupResourceKind, scoped.WriteConstraint{Resources: []scoped.ResourceConstraint{{
			Kind: svc.GroupResourceKind, ResourceID: strconv.FormatInt(a.GetID(), 10), TenantID: env.tenantID, ManagedScopeID: a.ManagedScopeID, Revision: strconv.FormatUint(a.GetVersion(), 10),
		}}}))
		if err := env.groupRepo.Update(ctx, a); err != nil {
			t.Fatalf("move parent with edited descendant: %v", err)
		}
		child, err = env.groupRepo.Get(env.backgroundCtx, child.GetID())
		if err != nil {
			t.Fatal(err)
		}
		if child.GetVersion() != childVersion || child.Path != a.Path+"/"+strconv.FormatInt(child.GetID(), 10) {
			t.Fatalf("child hierarchy or stored revision changed unexpectedly: %+v", child)
		}
	}
}
