package group

import (
	"context"
	"path/filepath"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-runtime/db/orm/lite"
	"gochen-runtime/db/sql/stdsql"
	hostauthz "gochen-runtime/host/authz"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/db"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func groupWriteGrantFixture(t *testing.T) (*GroupService, *gorm.DB, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "group-grants.db")
	storage, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.AutoMigrate(&iamentity.Group{}, &iamentity.User{}); err != nil {
		t.Fatal(err)
	}
	conn, err := storage.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	database, err := stdsql.NewWithContext(t.Context(), db.DBConfig{Driver: "sqlite3", Database: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	engine, err := lite.New(database)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := grouprepo.NewGroupRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	service := &GroupService{groupRepo: groups, userRepo: users, authorizer: svc.NewIAMAccess(nil)}
	if err := service.compileWriteApplications(); err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"*:*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, "platform")
	ctx, err = scoped.WithDataScope(ctx, scoped.Global())
	if err != nil {
		t.Fatal(err)
	}
	return service, storage, ctx
}

func TestGroupWriteOnePrimaryDecision(t *testing.T) {
	for _, http := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "http"}[http], func(t *testing.T) {
			s, storage, ctx := groupWriteGrantFixture(t)
			a := s.writeApplication
			if http {
				a = s.httpWriteApplication
			}
			decisions := 0
			descriptor, err := appcrud.Describe(a.options, true)
			if err != nil {
				t.Fatal(err)
			}
			var policies []auth.IPolicy
			if http {
				policies = append(policies, groupAssociationEntryPolicy{})
			}
			policies = append(policies, auth.PolicyFunc(func(context.Context, auth.Request) (auth.Decision, error) {
				decisions++
				return auth.Decision{Allowed: true, Spec: spec.All()}, nil
			}))
			compiled, err := s.authorizer.Compile(descriptor, s.groupRepo.ExecutionDescriptor().Metadata(), policies...)
			if err != nil {
				t.Fatal(err)
			}
			a.options.Authorizer = compiled
			for action := range a.resources {
				a.resources[action][0].Authorizer = compiled
			}
			item := &iamentity.Group{Name: "once"}
			if err := a.Create(ctx, item); err != nil {
				t.Fatal(err)
			}
			if decisions != 1 {
				t.Fatalf("create decisions=%d", decisions)
			}
			decisions = 0
			item.Description = "updated"
			if err := a.Update(ctx, item); err != nil {
				t.Fatal(err)
			}
			if decisions != 1 || item.Version != 1 {
				t.Fatalf("update decisions=%d item=%+v", decisions, item)
			}
			stale := *item
			stale.Version = 0
			if err := a.Update(ctx, &stale); !errors.Is(err, errors.Concurrency) {
				t.Fatalf("stale=%v", err)
			}
			decisions = 0
			if _, err := a.ExecuteBulk(ctx, appcrud.ActionUpdate, []int64{item.ID}, func(_ context.Context, g *iamentity.Group) error { g.Description = "bulk"; return nil }); err != nil {
				t.Fatal(err)
			}
			if decisions != 1 {
				t.Fatalf("bulk decisions=%d", decisions)
			}
			decisions = 0
			if err := a.Delete(ctx, item.ID); err != nil {
				t.Fatal(err)
			}
			if decisions != 1 {
				t.Fatalf("delete decisions=%d", decisions)
			}
			var stored iamentity.Group
			if err := storage.First(&stored, item.ID).Error; err != nil {
				t.Fatal(err)
			}
			if stored.DeletedAt == nil {
				t.Fatal("delete did not preserve soft deletion")
			}
		})
	}
}

func TestGroupWriteGrantBoundsAndLifetime(t *testing.T) {
	s, _, ctx := groupWriteGrantFixture(t)
	item := &iamentity.Group{Name: "primary"}
	if err := s.httpWriteApplication.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	var retained *appcrud.Application[*iamentity.Group, int64]
	command, err := newGroupWriteCommand(s.httpWriteApplication, appcrud.ActionUpdate, func(ctx context.Context, core *appcrud.Application[*iamentity.Group, int64], access *groupWriteAccess) (*iamentity.Group, error) {
		retained = core
		if err := core.Delete(ctx, item.ID); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("wrong action=%v", err)
		}
		if _, err := core.Execute(ctx, appcrud.ActionUpdate, item.ID+1, access.capture(func(context.Context, *iamentity.Group) error { return nil })); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("foreign target=%v", err)
		}
		return core.Execute(ctx, appcrud.ActionUpdate, item.ID, access.capture(func(_ context.Context, g *iamentity.Group) error { g.Description = "authorized"; return nil }))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, groupWriteInput{IDs: []int64{item.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := retained.Update(ctx, item); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired update=%v", err)
	}
	if err := retained.Delete(ctx, item.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired delete=%v", err)
	}
}
