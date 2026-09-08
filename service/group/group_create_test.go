package group_test

import (
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/auth/scoped"
	"gochen/errors"
)

func TestGroupRepoCreateWithInferredScope(t *testing.T) {
	for _, tc := range []struct {
		name            string
		child           bool
		authorizedScope int64
		forbidden       bool
	}{
		{name: "root"},
		{name: "child", child: true},
		{name: "different authorized scope", authorizedScope: 2, forbidden: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupGroupServiceTest(t)
			defer env.teardown(t)

			group := &iamentity.Group{TenantID: env.tenantID, Name: tc.name}
			pathPrefix, wantLevel := "", 1
			if tc.child {
				parent, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{
					TenantID: env.tenantID, Name: "parent",
				})
				if err != nil {
					t.Fatal(err)
				}
				parentID := parent.GetID()
				group.ParentID = &parentID
				pathPrefix, wantLevel = parent.Path, parent.Level+1
			}

			ctx, err := scoped.WithDataScope(env.backgroundCtx, scoped.Filtered(1))
			if err != nil {
				t.Fatal(err)
			}
			// 新建授权早于范围和 ID 补齐；层级字段应随首次写入完整持久化。
			ctx = scoped.WithConstraint(ctx, scoped.SingleEntityConstraint(svc.GroupResourceKind, scoped.WriteConstraint{
				Resources: []scoped.ResourceConstraint{{
					Kind: svc.GroupResourceKind, TenantID: env.tenantID, ManagedScopeID: tc.authorizedScope,
				}},
			}))
			err = env.groupRepo.Create(ctx, group)
			if tc.forbidden {
				if !errors.Is(err, errors.Forbidden) {
					t.Fatalf("expected forbidden, got %v", err)
				}
				var count int64
				if err := env.db.Model(&iamentity.Group{}).Where("name = ?", tc.name).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("unauthorized group was persisted: %d rows", count)
				}
				return
			}
			if err != nil {
				t.Fatalf("create group with inferred scope: %v", err)
			}
			stored, err := env.groupRepo.Get(ctx, group.GetID())
			if err != nil {
				t.Fatal(err)
			}
			wantPath := pathPrefix + "/" + strconv.FormatInt(group.GetID(), 10)
			if stored.GetID() <= 0 || stored.Path != wantPath || stored.Level != wantLevel {
				t.Fatalf("incomplete group hierarchy: id=%d path=%q level=%d", stored.GetID(), stored.Path, stored.Level)
			}
			if stored.TenantID != env.tenantID || stored.ManagedScopeID != 1 || stored.OwnerID != svc.TenantOwnerID(env.tenantID) {
				t.Fatalf("unexpected group boundary: tenant=%q scope=%d owner=%q", stored.TenantID, stored.ManagedScopeID, stored.OwnerID)
			}
		})
	}
}
