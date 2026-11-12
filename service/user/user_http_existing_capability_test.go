package user

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	userrepo "gochen-iam/repo/user"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserHTTPExistingCapabilitiesKeepTargetsOperationsAndLifetime(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"*:*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, action := range []string{appcrud.ActionUpdate, appcrud.ActionDelete} {
		id := int64(i + 99)
		user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: action, Email: action + "@example.test", Password: "password", Status: "active"}
		user.ID = id
		if err := storage.Create(user).Error; err != nil {
			t.Fatal(err)
		}
		var captured *appcrud.Application[*iamentity.User, int64]
		command, err := app.NewCommand(app.CommandOptions[[]int64, *userHTTPExistingAccess, struct{}]{Resources: service.httpExisting.resources[action],
			Access: func(_ context.Context, ids []int64, grants []*app.CommandGrant) (*userHTTPExistingAccess, error) {
				if _, err := service.httpExisting.bind(action, []int64{98}, grants); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("foreign intent=%v", err)
				}
				if _, err := service.httpExisting.bind(action, ids, nil); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("missing grants=%v", err)
				}
				impostor := &userrepo.UserRepo{Repo: service.userRepo.Repo}
				if _, err := app.NewCommandReader(impostor, grants[0], func(context.Context, int64, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
					t.Fatalf("different primary source=%v", err)
				}
				return service.httpExisting.bind(action, ids, grants)
			},
			Handler: func(ctx context.Context, _ []int64, access *userHTTPExistingAccess) (struct{}, error) {
				core := access.core
				captured = core
				if _, err := core.Get(ctx, 98); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("foreign read target=%v", err)
				}
				if _, err := core.List(ctx, 0, 10); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("directory access=%v", err)
				}
				if err := core.Create(ctx, user); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("creation through existing capability=%v", err)
				}
				if action == appcrud.ActionUpdate {
					if err := core.Delete(ctx, id); !errors.Is(err, errors.Forbidden) {
						t.Fatalf("delete through update capability=%v", err)
					}
				} else {
					copy, err := meta.Clone(user)
					if err != nil {
						return struct{}{}, err
					}
					copy.Avatar = "wrong-operation"
					if err := core.Update(ctx, copy); !errors.Is(err, errors.Forbidden) {
						t.Fatalf("update through delete capability=%v", err)
					}
				}
				other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"*:*:*"}})
				if err != nil {
					return struct{}{}, err
				}
				if _, err := core.Get(other, id); !errors.Is(err, errors.Forbidden) {
					t.Fatalf("changed identity=%v", err)
				}
				if action == appcrud.ActionUpdate {
					_, err := core.Execute(ctx, action, id, access.capture(func(_ context.Context, user *iamentity.User) error { user.Avatar = "authorized"; return nil }))
					return struct{}{}, err
				}
				return struct{}{}, core.Delete(ctx, id)
			}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := command.Execute(ctx, []int64{id}); err != nil {
			t.Fatal(err)
		}
		if _, err := captured.Get(ctx, id); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("expired primary read=%v", err)
		}
		if err := captured.Update(ctx, user); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("expired update access=%v", err)
		}
		if err := captured.Delete(ctx, id); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("expired delete access=%v", err)
		}
		var stored iamentity.User
		if err := storage.First(&stored, id).Error; err != nil {
			t.Fatal(err)
		}
		if action == appcrud.ActionUpdate && (stored.Avatar != "authorized" || stored.Version != 1 || stored.DeletedAt != nil) {
			t.Fatalf("incorrect authorized update=%+v", &stored)
		}
		if action == appcrud.ActionDelete && stored.DeletedAt == nil {
			t.Fatal("authorized delete did not preserve soft-delete behavior")
		}
	}
}

func TestUserHTTPUpdatePrimaryConditionAndDenialPreventWrites(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"*:*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test", Password: "password", Status: "active"}
	user.ID = 99
	if err := storage.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	for _, deny := range []bool{false, true} {
		executor := *service.httpExisting
		resources := append([]app.CommandResource[[]int64](nil), executor.resources[appcrud.ActionUpdate]...)
		descriptor, err := appcrud.Describe(executor.options, true)
		if err != nil {
			t.Fatal(err)
		}
		resources[0].Authorizer, err = service.authorizer.Compile(descriptor, service.userRepo.ExecutionDescriptor().Metadata(),
			userAssociationEntryPolicy{}, userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(999)), deny: deny})
		if err != nil {
			t.Fatal(err)
		}
		executor.options.Authorizer = resources[0].Authorizer
		entered := false
		command, err := app.NewCommand(app.CommandOptions[[]int64, *userHTTPExistingAccess, struct{}]{Resources: resources,
			Access: func(_ context.Context, ids []int64, grants []*app.CommandGrant) (*userHTTPExistingAccess, error) {
				entered = true
				return executor.bind(appcrud.ActionUpdate, ids, grants)
			},
			Handler: func(ctx context.Context, _ []int64, access *userHTTPExistingAccess) (struct{}, error) {
				_, err := access.core.Execute(ctx, appcrud.ActionUpdate, user.ID, access.capture(func(_ context.Context, item *iamentity.User) error { item.Avatar = "denied"; return nil }))
				return struct{}{}, err
			}})
		if err != nil {
			t.Fatal(err)
		}
		expected := errors.NotFound
		if deny {
			expected = errors.Forbidden
		}
		if _, err := command.Execute(ctx, []int64{user.ID}); !errors.Is(err, expected) || entered == deny {
			t.Fatalf("deny=%v error=%v accessEntered=%v", deny, err, entered)
		}
		var stored iamentity.User
		if err := storage.First(&stored, user.ID).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Version != 0 || stored.Password != "password" {
			t.Fatalf("snapshot condition did not prevent writes=%+v", &stored)
		}
	}
}
