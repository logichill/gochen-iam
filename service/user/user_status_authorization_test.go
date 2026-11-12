package user_test

import (
	"context"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	iamtenant "gochen-iam/tenant"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserStatusCommandsRejectBeforeResourceReads(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	reads, writes := &atomic.Int64{}, &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:status:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Update().Before("gorm:update").Register("user:status:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	untrusted, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithUserID(untrusted, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{untrusted, trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		for _, action := range []func(context.Context, int64) error{env.userService.ActivateUser, env.userService.DeactivateUser, env.userService.LockUser, env.userService.UnlockUser} {
			if err := action(ctx, 99); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("status denial=%v", err)
			}
		}
	}
	for _, action := range []string{"activate", "deactivate", "lock", "unlock"} {
		for _, test := range []struct {
			ctx  context.Context
			code errors.ErrorCode
		}{
			{userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), errors.Forbidden},
			{userAssociationPrincipal(t, env.tenantID, "trace", "platform", "user:api:write", "user:api:manage"), errors.Unauthorized},
			{nil, errors.InvalidInput},
		} {
			if err := env.userService.ExecuteStatusHTTP(test.ctx, action, 99); !errors.Is(err, test.code) {
				t.Fatalf("HTTP %s denial=%v, want %s", action, err, test.code)
			}
		}
		if err := env.userService.ExecuteStatusHTTP(untrusted, action, 0); !errors.Is(err, errors.InvalidInput) {
			t.Fatalf("invalid ID=%v", err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("rejected commands reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestUserStatusCommandsPreserveStatusAndScopeRules(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write", "user:api:manage")
	for _, action := range []struct {
		name, status string
		invoke       func(context.Context, int64) error
	}{
		{"deactivate", "inactive", env.userService.DeactivateUser},
		{"activate", "active", env.userService.ActivateUser},
		{"lock", "locked", env.userService.LockUser},
		{"unlock", "active", env.userService.UnlockUser},
	} {
		for _, http := range []bool{false, true} {
			var before iamentity.User
			if err := env.db.First(&before, user.ID).Error; err != nil {
				t.Fatal(err)
			}
			var err error
			if http {
				err = env.userService.ExecuteStatusHTTP(ctx, action.name, user.ID)
			} else {
				err = action.invoke(ctx, user.ID)
			}
			if err != nil {
				t.Fatalf("HTTP=%v %s=%v", http, action.name, err)
			}
			var stored iamentity.User
			if err := env.db.First(&stored, user.ID).Error; err != nil {
				t.Fatal(err)
			}
			if stored.Status != action.status || stored.Version != before.Version+1 || stored.OwnerID != before.OwnerID || stored.ManagedScopeID != before.ManagedScopeID || stored.Email != before.Email {
				t.Fatalf("HTTP=%v %s changed unexpected fields=%+v", http, action.name, &stored)
			}
		}
	}
	if err := env.db.Model(user).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	writes := &atomic.Int64{}
	if err := env.db.Callback().Update().Before("gorm:update").Register("user:status:scope", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"activate", "deactivate", "lock", "unlock"} {
		if err := env.userService.ExecuteStatusHTTP(ctx, action, user.ID); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("out-of-scope %s=%v", action, err)
		}
	}
	if writes.Load() != 0 {
		t.Fatalf("out-of-scope status wrote %d updates", writes.Load())
	}
	single := iamtenant.WithPolicy(userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
	if err := env.userService.ExecuteStatusHTTP(single, "activate", user.ID); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("single tenant lost its data condition=%v", err)
	}
	if err := env.userService.ExecuteStatusHTTP(env.backgroundCtx, "activate", user.ID); err != nil {
		t.Fatalf("System=%v", err)
	}
}

func TestUserStatusFactVersionConflictPreventsWrite(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "target", Email: "target@example.test", Status: "active"}
	user.ID = 99
	if err := env.db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	injected := &atomic.Bool{}
	if err := env.db.Callback().Query().After("gorm:query").Register("user:status:conflict", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" && injected.CompareAndSwap(false, true) {
			if err := env.db.Exec("UPDATE users SET version = version + 1 WHERE id = ?", user.ID).Error; err != nil {
				tx.AddError(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")
	if err := env.userService.LockUser(ctx, user.ID); !errors.Is(err, errors.Concurrency) {
		t.Fatalf("stale fact write=%v", err)
	}
	var stored iamentity.User
	if err := env.db.First(&stored, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != "active" || stored.Version != 1 || !injected.Load() {
		t.Fatalf("stale fact changed status=%+v", &stored)
	}
}
