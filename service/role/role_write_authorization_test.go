package role

import (
	"context"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-iam/tenant"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func roleWritePrincipal(t *testing.T, env *roleBulkTestEnv, subject, kind string, permissions ...string) context.Context {
	t.Helper()
	ctx := roleStatisticsPrincipal(t, env.tenantID, subject, kind, permissions...)
	ctx, err := scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	return tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})
}

func invokeRoleWrite(s *RoleService, ctx context.Context, action string, in RoleWriteInput, http bool) error {
	if http {
		return s.ExecuteWriteHTTP(ctx, action, in)
	}
	switch action {
	case "activate":
		return s.ActivateRole(ctx, in.ID)
	case "deactivate":
		return s.DeactivateRole(ctx, in.ID)
	default:
		return s.RemovePermission(ctx, in.ID, in.Permission)
	}
}

func TestRoleWritesRejectBeforeAllGormAccess(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	role := env.createTestRole(t, "write-target")
	var reads, writes atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("role-write:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("role-write:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trusted := roleWritePrincipal(t, env, "7", "tenant", "role:api:write", "role:api:manage")
	if err := env.roleService.ActivateRole(trusted, role.ID); err != nil {
		t.Fatal(err)
	}
	if reads.Load() == 0 || writes.Load() == 0 {
		t.Fatal("successful service did not reach the observed GORM path")
	}
	reads.Store(0)
	writes.Store(0)
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(base, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"activate", "deactivate", "remove_permission"} {
		for _, ctx := range []context.Context{base, trace, roleWritePrincipal(t, env, "7", "tenant", "role:api:read")} {
			if err := invokeRoleWrite(env.roleService, ctx, action, RoleWriteInput{ID: role.ID, Permission: "test:api:read"}, false); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("ordinary %s denial=%v", action, err)
			}
		}
		for _, test := range []struct {
			ctx  context.Context
			code errors.ErrorCode
		}{{nil, errors.InvalidInput}, {roleWritePrincipal(t, env, "7", "tenant", "role:api:write"), errors.Forbidden},
			{roleWritePrincipal(t, env, "opaque", "tenant", "role:api:write", "role:api:manage"), errors.Unauthorized},
			{roleStatisticsPrincipal(t, env.tenantID, "7", "department", "role:api:write", "role:api:manage"), errors.Forbidden}} {
			if err := invokeRoleWrite(env.roleService, test.ctx, action, RoleWriteInput{ID: role.ID}, true); !errors.Is(err, test.code) {
				t.Fatalf("HTTP %s denial=%v, want=%s", action, err, test.code)
			}
		}
		if err := invokeRoleWrite(env.roleService, trusted, action, RoleWriteInput{}, true); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("zero ID %s=%v", action, err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied writes reached GORM reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestRoleWritesPreserveSystemRoleScopeVersionAndPermissionBehavior(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	role := env.createTestRole(t, "write-target")
	ctx := roleWritePrincipal(t, env, "7", "department", "role:api:write", "role:api:manage")
	for _, action := range []string{"deactivate", "activate"} {
		for _, http := range []bool{false, true} {
			var before, after iamentity.Role
			if err := env.db.First(&before, role.ID).Error; err != nil {
				t.Fatal(err)
			}
			if err := invokeRoleWrite(env.roleService, ctx, action, RoleWriteInput{ID: role.ID, Permission: "test:api:read"}, http); err != nil {
				t.Fatalf("%s HTTP=%v error=%v", action, http, err)
			}
			if err := env.db.First(&after, role.ID).Error; err != nil {
				t.Fatal(err)
			}
			status := "active"
			if action == "deactivate" {
				status = "inactive"
			}
			if after.Status != status || after.Version != before.Version+1 || after.NamespaceScopeID != before.NamespaceScopeID || after.OwnerID != before.OwnerID || after.Name != before.Name {
				t.Fatalf("%s changed unexpected fields: %+v", action, &after)
			}
		}
	}
	if err := env.db.Exec("UPDATE roles SET is_system = ? WHERE id = ?", true, role.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"deactivate", "remove_permission"} {
		if err := invokeRoleWrite(env.roleService, env.backgroundCtx, action, RoleWriteInput{ID: role.ID}, false); !errors.Is(err, errors.Validation) {
			t.Fatalf("system role %s=%v", action, err)
		}
	}
	if err := env.roleService.ActivateRole(env.backgroundCtx, role.ID); err != nil {
		t.Fatalf("System may activate system role: %v", err)
	}
	if err := env.db.Exec("UPDATE roles SET namespace_scope_id = ? WHERE id = ?", 2, role.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"activate", "deactivate", "remove_permission"} {
		if err := invokeRoleWrite(env.roleService, ctx, action, RoleWriteInput{ID: role.ID}, false); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("outside namespace %s=%v", action, err)
		}
	}
}

func TestRolePermissionRemovalPersistsEmptySet(t *testing.T) {
	for _, http := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "HTTP_command"}[http], func(t *testing.T) {
			env := setupRoleBulkTest(t)
			defer env.teardown(t)
			role := env.createTestRole(t, "permission-target")
			ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write", "role:api:manage")
			if err := invokeRoleWrite(env.roleService, ctx, "remove_permission", RoleWriteInput{ID: role.ID, Permission: "test:api:read"}, http); err != nil {
				t.Fatal(err)
			}
			var stored iamentity.Role
			if err := env.db.First(&stored, role.ID).Error; err != nil {
				t.Fatal(err)
			}
			if len(stored.Permissions) != 0 {
				t.Fatalf("permission removal retained=%q", stored.Permissions)
			}
		})
	}
}

func TestRoleWriteFrozenVersionAndPersistenceFailuresKeepState(t *testing.T) {
	for _, mode := range []string{"version", "owner", "failure"} {
		t.Run(mode, func(t *testing.T) {
			env := setupRoleBulkTest(t)
			defer env.teardown(t)
			role := env.createTestRole(t, "frozen-role")
			var once atomic.Bool
			if mode == "failure" {
				if err := env.db.Callback().Update().Before("gorm:update").Register("role-write:failure", func(tx *gorm.DB) {
					if tx.Statement.Table == "roles" {
						tx.AddError(errors.NewCode(errors.Database, "injected write failure"))
					}
				}); err != nil {
					t.Fatal(err)
				}
			} else if err := env.db.Callback().Query().After("gorm:query").Register("role-write:drift", func(tx *gorm.DB) {
				if tx.Statement.Table == "roles" && once.CompareAndSwap(false, true) {
					statement := "UPDATE roles SET version = version + 1 WHERE id = ?"
					if mode == "owner" {
						statement = "UPDATE roles SET owner_id = 'drift' WHERE id = ?"
					}
					if err := env.db.Exec(statement, role.ID).Error; err != nil {
						t.Error(err)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			err := env.roleService.DeactivateRole(env.backgroundCtx, role.ID)
			code := errors.Concurrency
			if mode == "failure" {
				code = errors.Database
			} else if mode == "owner" {
				code = errors.Forbidden
			}
			if !errors.Is(err, code) {
				t.Fatalf("%s write=%v want=%s", mode, err, code)
			}
			var stored iamentity.Role
			if err := env.db.First(&stored, role.ID).Error; err != nil || stored.Status != "active" {
				t.Fatalf("rejected write persisted status: %+v error=%v", &stored, err)
			}
		})
	}
}
