package group_test

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestGroupStatisticsRejectsBeforeReadingAllResources(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	for _, ctx := range []context.Context{t.Context(), associationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		if _, err := env.groupService.GroupStatistics(ctx); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("statistics denial=%v", err)
		}
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "tenant", "group:api:read")
	if _, err := env.groupService.GroupStatisticsHTTP(ctx); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("HTTP entry denial=%v", err)
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denial reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestGroupStatisticsCountsEachResourceWithinTenantAndScope(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	createAssociationGroup(t, env)
	for _, name := range []string{"outside-scope", "outside-tenant"} {
		g, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if name == "outside-scope" {
			err = env.db.Model(g).Update("managed_scope_id", 2).Error
		} else {
			err = env.db.Model(g).Update("tenant_id", "other").Error
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	u1 := env.createTestUser(t, "visible", "visible@example.com")
	u2 := env.createTestUser(t, "hidden", "hidden@example.com")
	u3 := env.createTestUser(t, "other-tenant", "other@example.com")
	for _, mutation := range []struct {
		user   *iamentity.User
		values map[string]any
	}{
		{u1, map[string]any{"status": svc.UserStatusActive}},
		{u2, map[string]any{"managed_scope_id": 2, "status": svc.UserStatusInactive}},
		{u3, map[string]any{"tenant_id": "other", "status": svc.UserStatusActive}},
	} {
		if err := env.db.Model(mutation.user).Updates(mutation.values).Error; err != nil {
			t.Fatal(err)
		}
	}
	env.createTestRole(t, "visible-role")
	r2 := env.createTestRole(t, "hidden-role")
	r3 := env.createTestRole(t, "other-role")
	if err := env.db.Model(r2).Update("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Model(r3).Update("tenant_id", "other").Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Query().Before("gorm:query").Register("statistics:test:no-hydration", func(tx *gorm.DB) {
		if tx.Statement.Table != "groups" && tx.Statement.Table != "users" && tx.Statement.Table != "roles" {
			tx.AddError(errors.NewCode(errors.Internal, "statistics read an undeclared resource"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read", "group:api:manage")
	for _, invoke := range []func(context.Context) (*svc.StatisticsResponse, error){env.groupService.GroupStatistics, env.groupService.GroupStatisticsHTTP} {
		result, err := invoke(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if result.TotalGroups != 1 || result.TotalUsers != 1 || result.ActiveUsers != 1 || result.TotalRoles != 1 ||
			result.GroupsByLevel[1] != 1 || result.UsersByStatus[svc.UserStatusActive] != 1 || len(result.UsersByStatus) != 1 {
			t.Fatalf("scoped statistics=%+v", result)
		}
	}
	result, err := env.groupService.GroupStatistics(env.backgroundCtx)
	if err != nil || result.TotalGroups != 2 || result.TotalUsers != 2 || result.TotalRoles != 2 || result.ActiveUsers != 1 {
		t.Fatalf("system tenant statistics=%+v error=%v", result, err)
	}
}
