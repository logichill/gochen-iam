package user

import (
	"context"
	"path/filepath"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen-runtime/db/orm/lite"
	ormrepo "gochen-runtime/db/orm/repo"
	"gochen-runtime/db/sql/stdsql"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/db"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func userAssociationCapabilityFixture(t *testing.T) (*UserService, *gorm.DB, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "association-capabilities.db")
	storage, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.AutoMigrate(&iamentity.User{}, &iamentity.Group{}, &iamentity.Role{}, &iamentity.Scope{}, &iamentity.UserRoleBinding{}); err != nil {
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
	users, err := userrepo.NewUserRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	groups, err := grouprepo.NewGroupRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(engine, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewUserService(users, groups, roles, nil, svc.NewIAMAccess(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := contextx.WithTenantID(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:read"}})
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

type userAssociationCondition struct {
	condition spec.Spec
	deny      bool
}

func (userAssociationCondition) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByDimension("scope")}}
}
func (p userAssociationCondition) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: !p.deny, Spec: p.condition}, nil
}

func TestUserAssociationCapabilitiesKeepIndependentConditionsAndTrustedSources(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	member := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 3, HomeTenantID: "tenant-a", HomeScopeID: 3, OwnerID: "owner", Username: "member", Email: "member@example.test"}
	member.ID = 50
	group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: 2, OwnerID: "owner", Name: "group"}
	group.ID = 100
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 4, OwnerID: "owner", Name: "role"}
	role.ID = 500
	for _, item := range []any{user, member, group, role} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (99, 100), (50, 100)").Error; err != nil {
		t.Fatal(err)
	}
	if err := storage.Exec("INSERT INTO group_roles (group_id, role_id) VALUES (100, 500)").Error; err != nil {
		t.Fatal(err)
	}
	names := []string{"user", "groups", "members", "roles"}
	var resources []app.CommandResource[UserAssociationReadInput]
	for i, name := range names {
		provider, kind := service.associationReadProvider(name, nil)
		descriptor := auth.Descriptor{Resource: kind, Actions: []auth.Action{{Name: "groups_" + name, Kind: auth.KindList, Permission: "user:api:read"}}}
		authorizer, err := service.authorizer.Compile(descriptor, provider.ExecutionDescriptor().Metadata(), userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+1))})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[UserAssociationReadInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: "groups_" + name,
			Intent: func(UserAssociationReadInput) (auth.Request, error) { return auth.Request{}, nil }})
	}
	var captured *userAssociationReadAccess
	command, err := app.NewCommand(app.CommandOptions[UserAssociationReadInput, *userAssociationReadAccess, UserAssociationReadResult]{Resources: resources,
		Access: func(_ context.Context, in UserAssociationReadInput, grants []*app.CommandGrant) (*userAssociationReadAccess, error) {
			if _, err := service.bindAssociationRead("groups", in, names, nil, grants[:3]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grant=%v", err)
			}
			if _, err := service.bindAssociationRead("roles", in, names, nil, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong action=%v", err)
			}
			impostor, err := ormrepo.NewRepo[*iamentity.Group, int64](service.groupRepo.Orm(), "groups", ormrepo.WithResourceKind[*iamentity.Group, int64](svc.GroupResourceKind), ormrepo.WithIsolation[*iamentity.Group, int64](ormrepo.IsolationCols{Column: "tenant_id"}))
			if err != nil {
				return nil, err
			}
			if _, err := app.NewCommandReader(impostor, grants[1], func(context.Context, struct{}, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("impostor provider=%v", err)
			}
			return service.bindAssociationRead("groups", in, names, nil, grants)
		},
		Handler: func(ctx context.Context, in UserAssociationReadInput, access *userAssociationReadAccess) (UserAssociationReadResult, error) {
			captured = access
			if _, err := access.groups.Read(ctx, in.ID); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("group source before primary read=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:read"}})
			if err != nil {
				return UserAssociationReadResult{}, err
			}
			if _, err := access.user.Read(other, in.ID); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("other identity=%v", err)
			}
			result, err := executeUserAssociationRead(ctx, "groups", in, access)
			if err != nil {
				return result, err
			}
			if _, err := access.user.Read(ctx, 50); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("other primary=%v", err)
			}
			if _, err := access.groups.Read(ctx, 50); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("other user association=%v", err)
			}
			if _, err := access.parents.Read(ctx, []int64{888}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("unrelated parent=%v", err)
			}
			if _, err := access.members.Read(ctx, []int64{888}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("unrelated member group=%v", err)
			}
			if _, err := access.roles.Read(ctx, []int64{888}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("unrelated role group=%v", err)
			}
			return result, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := command.Execute(ctx, UserAssociationReadInput{ID: user.ID})
	if err != nil || len(result.Groups) != 1 || len(result.Groups[0].Users) != 1 || result.Groups[0].Users[0].ID != member.ID || len(result.Groups[0].DefaultRoles) != 1 || result.Groups[0].DefaultRoles[0].ID != role.ID {
		t.Fatalf("independent conditions result=%+v error=%v", result, err)
	}
	if _, err := captured.user.Read(ctx, user.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired primary=%v", err)
	}
	if _, err := captured.groups.Read(ctx, user.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired groups=%v", err)
	}
	if _, err := captured.members.Read(ctx, []int64{group.ID}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired members=%v", err)
	}
	if _, err := captured.roles.Read(ctx, []int64{group.ID}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired roles=%v", err)
	}
	// A later resource denial prevents the access factory and primary query.
	denied, err := service.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "groups_roles", Kind: auth.KindList, Permission: "user:api:read"}}}, service.roleRepo.ExecutionDescriptor().Metadata(), userAssociationCondition{deny: true, condition: spec.All()})
	if err != nil {
		t.Fatal(err)
	}
	resources[3].Authorizer = denied
	called := false
	rejected, err := app.NewCommand(app.CommandOptions[UserAssociationReadInput, *userAssociationReadAccess, UserAssociationReadResult]{Resources: resources,
		Access: func(context.Context, UserAssociationReadInput, []*app.CommandGrant) (*userAssociationReadAccess, error) {
			called = true
			return nil, nil
		},
		Handler: func(context.Context, UserAssociationReadInput, *userAssociationReadAccess) (UserAssociationReadResult, error) {
			called = true
			return UserAssociationReadResult{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rejected.Execute(ctx, UserAssociationReadInput{ID: user.ID}); !errors.Is(err, errors.Forbidden) || called {
		t.Fatalf("later denial=%v reached business=%v", err, called)
	}
}
