package user_test

import (
	"context"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserHTTPCreateAuthorizationAndAssociationRejectionHaveZeroGormWrites(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	var reads, writes atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("user-create:read", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Create().Before("gorm:create").Register("user-create:write", func(*gorm.DB) { writes.Add(1) }); err != nil {
		t.Fatal(err)
	}
	newUser := func(name string) *iamentity.User {
		return &iamentity.User{Username: name, Email: name + "@example.test", Password: "secret-password"}
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:manage", "user:api:write")
	if err := env.userService.CreateHTTP(ctx, newUser("observed")); err != nil {
		t.Fatal(err)
	}
	if writes.Load() == 0 {
		t.Fatal("observer did not detect actual authorized creation")
	}
	reads.Store(0)
	writes.Store(0)
	base, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := contextx.WithUserID(base, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []context.Context{nil, base, tracked,
		userAssociationPrincipal(t, env.tenantID, "opaque", "platform", "*:*:*"),
		userAssociationPrincipal(t, env.tenantID, "7", "org", "*:*:*"),
		userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write"),
		userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:manage"),
	} {
		if err := env.userService.CreateHTTP(denied, newUser("denied")); err == nil {
			t.Fatal("invalid create identity or permission allowed")
		}
		calls := 0
		if _, err := env.userService.ExecuteNewHTTP(denied, appcrud.ActionCreate, func(context.Context) (*iamentity.User, error) { calls++; return newUser("denied"), nil }); err == nil || calls != 0 {
			t.Fatalf("denied factory calls=%d error=%v", calls, err)
		}
		if _, err := env.userService.ExecuteNewBulkHTTP(denied, appcrud.ActionCreate, func(context.Context) ([]*iamentity.User, error) {
			calls++
			return []*iamentity.User{newUser("denied")}, nil
		}); err == nil || calls != 0 {
			t.Fatalf("denied bulk factory calls=%d error=%v", calls, err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied create resources reads=%d writes=%d", reads.Load(), writes.Load())
	}
	for _, relation := range []string{"groups", "roles"} {
		item := newUser("association")
		if relation == "groups" {
			item.Groups = []iamentity.Group{{Name: "forged"}}
		} else {
			item.Roles = []iamentity.Role{{Name: "forged"}}
		}
		if err := env.userService.CreateHTTP(ctx, item); !errors.Is(err, errors.Validation) {
			t.Fatalf("%s create error=%v", relation, err)
		}
	}
	if writes.Load() != 0 {
		t.Fatal("rejected create association reached GORM")
	}
}

func TestUserHTTPCreateSecondWriteFailureRollsBackEntireBatch(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	var writes atomic.Int64
	if err := env.db.Callback().Create().Before("gorm:create").Register("user-create:second-fault", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" && writes.Add(1) == 2 {
			tx.AddError(errors.NewCode(errors.Database, "injected second create failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:manage", "user:api:write")
	_, err := env.userService.ExecuteNewBulkHTTP(ctx, appcrud.ActionCreate, func(context.Context) ([]*iamentity.User, error) {
		return []*iamentity.User{{Username: "batch-one", Email: "one@example.test", Password: "secret-one"}, {Username: "batch-two", Email: "two@example.test", Password: "secret-two"}}, nil
	})
	if err == nil || writes.Load() != 2 {
		t.Fatalf("injected failure writes=%d error=%v", writes.Load(), err)
	}
	var count int64
	if err := env.db.Model(&iamentity.User{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("batch partially saved users=%d error=%v", count, err)
	}
}
