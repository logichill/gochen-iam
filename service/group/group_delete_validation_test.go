package group_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestGroupDeleteValidationRejectsBeforeResourceAccess(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	for _, ctx := range []context.Context{t.Context(), associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")} {
		if err := env.groupService.ValidateDelete(ctx, 1); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("delete validation denial=%v", err)
		}
	}
	untrusted, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.groupService.DeleteGroup(untrusted, env.tenantID, 1); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("delete denial=%v", err)
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("delete validation denial reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupDeleteChecksSameTenantAssociationsOutsideVisibleScopes(t *testing.T) {
	for _, related := range []string{"child", "member"} {
		t.Run(related, func(t *testing.T) {
			env := setupGroupServiceTest(t)
			defer env.teardown(t)
			group := createAssociationGroup(t, env)
			var target any
			if related == "child" {
				id := group.GetID()
				child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "hidden-child", ParentID: &id})
				if err != nil {
					t.Fatal(err)
				}
				target = child
			} else {
				user := env.createTestUser(t, "hidden-member", "hidden@example.com")
				if err := env.groupService.AddUserToGroup(env.backgroundCtx, group.GetID(), user.GetID()); err != nil {
					t.Fatal(err)
				}
				target = user
			}
			if err := env.db.Model(target).Update("managed_scope_id", 2).Error; err != nil {
				t.Fatal(err)
			}
			_, writes := countAssociationAccess(t, env.db)
			ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:delete")
			if err := env.groupService.DeleteGroup(ctx, env.tenantID, group.GetID()); !errors.Is(err, errors.Validation) || writes.Load() != 0 {
				t.Fatalf("hidden %s deletion=%v writes=%d", related, err, writes.Load())
			}
			var stored iamentity.Group
			if err := env.db.First(&stored, group.GetID()).Error; err != nil || stored.DeletedAt != nil {
				t.Fatalf("group changed after existence denial=%+v error=%v", stored, err)
			}
		})
	}
}

func TestGroupDeleteRollsBackOnConcurrentRevision(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	var injected atomic.Bool
	if err := env.db.Callback().Update().Before("gorm:update").Register("group-delete:revision-change", func(tx *gorm.DB) {
		if tx.Statement.Table == "groups" && injected.CompareAndSwap(false, true) {
			if err := tx.Exec("UPDATE groups SET version = version + 1 WHERE id = ?", group.GetID()).Error; err != nil {
				tx.AddError(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:delete")
	if err := env.groupService.DeleteGroup(ctx, env.tenantID, group.GetID()); !errors.Is(err, errors.Concurrency) || !injected.Load() {
		t.Fatalf("concurrent deletion=%v injected=%v", err, injected.Load())
	}
	var stored struct {
		DeletedAt *time.Time
		Version   uint64
	}
	if err := env.db.Table("groups").Select("deleted_at, version").Where("id = ?", group.GetID()).Take(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.DeletedAt != nil || stored.Version != group.GetVersion() {
		t.Fatalf("failed deletion left changes=%+v", stored)
	}
}

func TestGroupDeleteValidationCountsWithoutHydratingRelations(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	group := createAssociationGroup(t, env)
	id := group.GetID()
	child, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "child", ParentID: &id})
	if err != nil {
		t.Fatal(err)
	}
	user := env.createTestUser(t, "member", "member@example.com")
	if err := env.groupService.AddUserToGroup(env.backgroundCtx, id, user.GetID()); err != nil {
		t.Fatal(err)
	}
	_, writes := countAssociationAccess(t, env.db)
	if err := env.db.Callback().Query().Before("gorm:query").Register("delete-validation:no-relations", func(tx *gorm.DB) {
		if len(tx.Statement.Preloads) > 0 || (tx.Statement.Table != "groups" && tx.Statement.Table != "users") {
			tx.AddError(errors.NewCode(errors.Internal, "delete validation read an undeclared relation"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:delete")
	if err := env.groupService.ValidateDelete(ctx, id); !errors.Is(err, errors.Validation) || writes.Load() != 0 {
		t.Fatalf("child validation=%v writes=%d", err, writes.Load())
	}
	if err := env.db.Model(child).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	writes.Store(0)
	if err := env.groupService.ValidateDelete(ctx, id); !errors.Is(err, errors.Validation) || writes.Load() != 0 {
		t.Fatalf("member validation=%v writes=%d", err, writes.Load())
	}
	if err := env.db.Model(user).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	writes.Store(0)
	if err := env.groupService.ValidateDelete(ctx, id); err != nil || writes.Load() != 0 {
		t.Fatalf("empty group validation=%v writes=%d", err, writes.Load())
	}
}
