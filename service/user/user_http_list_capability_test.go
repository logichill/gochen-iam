package user

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/app/query"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserHTTPListCapabilitiesUseIndependentConditionsAndTrustedSources(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:read", "user:api:manage"}})
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: 2, OwnerID: "owner", Name: "group"}
	group.ID = 100
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 3, OwnerID: "owner", Name: "role"}
	role.ID = 101
	for _, entity := range []any{user, group, role, &iamentity.UserRoleBinding{UserID: 99, RoleID: 101, GrantScopeID: 1, Status: "active"}} {
		if err := storage.Create(entity).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", 99, 100).Error; err != nil {
		t.Fatal(err)
	}
	options := appcrud.Options[*iamentity.User, int64]{Resource: "user", ActionPermissions: map[string]string{
		appcrud.ActionRead: "user:api:read", appcrud.ActionList: "user:api:read",
	}}
	descriptor, err := appcrud.Describe(options, false)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := service.authorizer.Compile(descriptor, service.userRepo.Repo.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{}, userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(1))})
	if err != nil {
		t.Fatal(err)
	}
	options.Authorizer = primary
	resources := []app.CommandResource[query.QueryOptions]{{Name: "users", Repository: service.userRepo.Repo, Authorizer: primary, Action: "list",
		Intent: func(query.QueryOptions) (auth.Request, error) { return auth.Request{}, nil }}}
	for i, name := range []string{"groups", "roles"} {
		provider, resource := service.directoryProvider(name)
		authorizer, err := service.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: "http_list_" + name, Kind: auth.KindList, Permission: "user:api:read"}}},
			provider.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{}, userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+2))})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[query.QueryOptions]{Name: name, Repository: provider, Authorizer: authorizer, Action: "http_list_" + name,
			Intent: func(query.QueryOptions) (auth.Request, error) { return auth.Request{}, nil }})
	}
	var captured *userHTTPListAccess
	command, err := app.NewCommand(app.CommandOptions[query.QueryOptions, *userHTTPListAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, _ query.QueryOptions, grants []*app.CommandGrant) (*userHTTPListAccess, error) {
			if _, err := service.bindHTTPList(options, grants[:1]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grants=%v", err)
			}
			if _, err := service.bindHTTPList(options, []*app.CommandGrant{grants[0], grants[2], grants[1]}); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("reordered grants=%v", err)
			}
			impostor, err := ormrepo.NewRepo[*iamentity.Group, int64](service.groupRepo.Orm(), "groups", ormrepo.WithResourceKind[*iamentity.Group, int64](svc.GroupResourceKind))
			if err != nil {
				return nil, err
			}
			if _, err := app.NewCommandReader(impostor, grants[1], func(context.Context, []int64, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("different provider=%v", err)
			}
			return service.bindHTTPList(options, grants)
		},
		Handler: func(ctx context.Context, in query.QueryOptions, access *userHTTPListAccess) (struct{}, error) {
			captured = access
			if _, err := access.groups.Read(ctx, []int64{user.ID}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("association before trusted primary=%v", err)
			}
			found, err := access.users.Query(ctx, in)
			if err != nil || len(found) != 1 || found[0].ID != user.ID {
				t.Fatalf("primary condition found=%+v error=%v", found, err)
			}
			groups, err := access.groups.Read(ctx, []int64{user.ID})
			if err != nil || len(groups.Items) != 1 || groups.Items[0].ID != group.ID {
				t.Fatalf("independent group condition found=%+v error=%v", groups, err)
			}
			roles, err := access.roles.Read(ctx, []int64{user.ID})
			if err != nil || len(roles.Items) != 1 || roles.Items[0].ID != role.ID {
				t.Fatalf("independent role condition found=%+v error=%v", roles, err)
			}
			if _, err := access.roles.Read(ctx, []int64{98}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("foreign association source=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:read", "user:api:manage"}})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.groups.Read(other, []int64{user.ID}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, query.QueryOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := captured.groups.Read(ctx, []int64{user.ID}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired group capability=%v", err)
	}
	if _, err := captured.users.Query(ctx, query.QueryOptions{}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired primary capability=%v", err)
	}

	deny, err := service.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind, Actions: []auth.Action{{Name: "http_list_roles", Kind: auth.KindList, Permission: "user:api:read"}}},
		service.roleRepo.Repo.ExecutionDescriptor().Metadata(), userAssociationCondition{deny: true, condition: spec.All()})
	if err != nil {
		t.Fatal(err)
	}
	resources[2].Authorizer = deny
	called := false
	rejected, err := app.NewCommand(app.CommandOptions[query.QueryOptions, struct{}, struct{}]{Resources: resources,
		Access: func(context.Context, query.QueryOptions, []*app.CommandGrant) (struct{}, error) {
			called = true
			return struct{}{}, nil
		},
		Handler: func(context.Context, query.QueryOptions, struct{}) (struct{}, error) {
			called = true
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rejected.Execute(ctx, query.QueryOptions{}); !errors.Is(err, errors.Forbidden) || called {
		t.Fatalf("later resource rejection error=%v handlerCalled=%v", err, called)
	}
}
