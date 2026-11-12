package role

import (
	"context"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
	"sync/atomic"
	"testing"
)

func TestRoleCustomExecutionsRejectBeforeResourceAccess(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	var reads, writes atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("custom-role:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("custom-role:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{ctx, roleWritePrincipal(t, env, "7", "tenant", "other:api:read")} {
		for _, call := range []func(context.Context) error{
			func(ctx context.Context) error { _, err := env.roleService.RolePermissions(ctx, 1); return err },
			func(ctx context.Context) error { return env.roleService.AddPermission(ctx, 1, "test:api:read") },
			func(ctx context.Context) error { _, err := env.roleService.RoleUsers(ctx, 1); return err },
			func(ctx context.Context) error { _, err := env.roleService.RoleGroups(ctx, 1); return err },
			func(ctx context.Context) error { return env.roleService.AssignRoleToUser(ctx, 1, 2) },
			func(ctx context.Context) error { return env.roleService.RemoveRoleFromUser(ctx, 1, 2) },
			func(ctx context.Context) error { _, err := env.roleService.CloneRole(ctx, 1, "cloned"); return err },
			func(ctx context.Context) error { return env.roleService.InitializeSystemRoles(ctx, env.tenantID) },
		} {
			if err := call(ctx); !errors.Is(err, errors.Forbidden) && !errors.Is(err, errors.Unauthorized) {
				t.Fatalf("missing identity denial=%v", err)
			}
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("rejected custom actions accessed storage reads=%d writes=%d", reads.Load(), writes.Load())
	}
}
