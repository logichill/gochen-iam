package user

import (
	"context"
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func selfCapabilityResources(t *testing.T, s *UserService, action string, names []string, denyLast bool) ([]app.CommandResource[userSelfInput], *auth.Fact[*iamentity.User]) {
	t.Helper()
	target, err := auth.NewFact("test.self.user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		t.Fatal(err)
	}
	resources := make([]app.CommandResource[userSelfInput], 0, len(names))
	for i, name := range names {
		provider, resource := s.selfProvider(name)
		policy, kind := userSelfPolicy{}, auth.KindList
		if name == "user" {
			policy.target, policy.write, kind = target, action != "profile", auth.KindRead
			if policy.write {
				kind = auth.KindUpdate
			}
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource,
			Actions: []auth.Action{{Name: action + "_" + name, Kind: kind, Permission: "user:self:read"}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "test.self." + name, System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{policy,
				userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+1)), deny: denyLast && i == len(names)-1}}}}},
			auth.CompileOptions{Metadata: provider.ExecutionDescriptor().Metadata(), Checker: auth.ActionCheckerFunc(func(ctx context.Context, _ string) error {
				_, err := hostauthz.RequirePrincipal(ctx)
				return err
			})})
		if err != nil {
			t.Fatal(err)
		}
		resourceName := name
		resources = append(resources, app.CommandResource[userSelfInput]{Name: name, Repository: provider, Authorizer: authorizer, Action: action + "_" + name,
			Intent: func(in userSelfInput) (auth.Request, error) {
				if resourceName == "user" {
					return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
				}
				return auth.Request{}, nil
			}})
	}
	return resources, target
}

func TestUserSelfCapabilitiesExecuteIndependentConditionsAndBoundaries(t *testing.T) {
	s, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "99", ActiveScopeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Global())
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "self", Email: "self@example.test", Password: "password"}
	user.ID = 99
	group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: 2, OwnerID: "owner", Name: "group"}
	group.ID = 100
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 3, OwnerID: "owner", Name: "role"}
	role.ID = 101
	for _, entity := range []any{user, group, role, &iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: 1, Status: "inactive"}} {
		if err := storage.Create(entity).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, group.ID).Error; err != nil {
		t.Fatal(err)
	}
	names := []string{"user", "groups", "roles"}
	resources, target := selfCapabilityResources(t, s, "profile", names, false)
	var captured *userSelfAccess
	command, err := app.NewCommand(app.CommandOptions[userSelfInput, *userSelfAccess, struct{}]{Resources: resources,
		Access: func(ctx context.Context, in userSelfInput, grants []*app.CommandGrant) (*userSelfAccess, error) {
			if _, err := s.bindSelf(ctx, "profile", in, names, target, grants[:1]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grants=%v", err)
			}
			if _, err := s.bindSelf(ctx, "profile", userSelfInput{ID: 7}, names, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed target=%v", err)
			}
			if _, err := s.bindSelf(ctx, "update_profile", in, names, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed action=%v", err)
			}
			impostor := &userrepo.UserRepo{Repo: s.userRepo.Repo}
			if _, err := app.NewCommandRepository(impostor, grants[0]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("different primary provider=%v", err)
			}
			if _, err := app.NewCommandReader(s.roleRepo.Repo, grants[1], func(context.Context, int64, spec.Spec) (bool, error) { return true, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("different relation provider=%v", err)
			}
			return s.bindSelf(ctx, "profile", in, names, target, grants)
		},
		Handler: func(ctx context.Context, in userSelfInput, access *userSelfAccess) (struct{}, error) {
			captured = access
			result, err := s.executeSelfAction(ctx, "profile", in, access, target)
			if err != nil || len(result.Groups) != 1 || result.Groups[0].ID != group.ID || len(result.Roles) != 1 || result.Roles[0].ID != role.ID {
				t.Fatalf("independent conditions result=%+v error=%v", result, err)
			}
			if _, err := access.groups.Read(ctx, 7); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("foreign relation source=%v", err)
			}
			if _, err := access.users.Get(ctx, 7); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("foreign primary source=%v", err)
			}
			if err := access.users.Update(ctx, user); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("write through read grant=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.roles.Read(other, user.ID); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, userSelfInput{ID: user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := captured.roles.Read(ctx, user.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired role capability=%v", err)
	}
	if _, err := captured.users.Get(ctx, user.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired primary capability=%v", err)
	}

	resources, target = selfCapabilityResources(t, s, "profile", names, true)
	called := false
	rejected, err := app.NewCommand(app.CommandOptions[userSelfInput, struct{}, struct{}]{Resources: resources,
		Access: func(context.Context, userSelfInput, []*app.CommandGrant) (struct{}, error) {
			called = true
			return struct{}{}, nil
		},
		Handler: func(context.Context, userSelfInput, struct{}) (struct{}, error) {
			called = true
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rejected.Execute(ctx, userSelfInput{ID: user.ID}); !errors.Is(err, errors.Forbidden) || called {
		t.Fatalf("later rejection=%v factory/handler=%v", err, called)
	}

	occupied := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 2, ManagedScopeID: 2, OwnerID: "owner", Username: "occupied", Email: "occupied@example.test"}
	occupied.ID = 100
	if err := storage.Create(occupied).Error; err != nil {
		t.Fatal(err)
	}
	names = []string{"user", "email"}
	resources, target = selfCapabilityResources(t, s, "update_profile", names, false)
	var writer *userSelfAccess
	update, err := app.NewCommand(app.CommandOptions[userSelfInput, *userSelfAccess, struct{}]{Resources: resources,
		Access: func(ctx context.Context, in userSelfInput, grants []*app.CommandGrant) (*userSelfAccess, error) {
			return s.bindSelf(ctx, "update_profile", in, names, target, grants)
		},
		Handler: func(ctx context.Context, in userSelfInput, access *userSelfAccess) (struct{}, error) {
			writer = access
			used, err := access.email.Read(ctx, in.Profile.Email)
			if err != nil || !used {
				t.Fatalf("independent email condition used=%v error=%v", used, err)
			}
			if _, err := access.email.Read(ctx, "arbitrary@example.test"); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed email=%v", err)
			}
			current, err := access.users.FromFact(ctx, target)
			if err != nil {
				return struct{}{}, err
			}
			current.OwnerID = "forged"
			if err := access.users.Update(ctx, current); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("ownership widening=%v", err)
			}
			current.OwnerID = "owner"
			current.Version++
			if err := access.users.Update(ctx, current); !errors.Is(err, errors.Concurrency) {
				t.Fatalf("version widening=%v", err)
			}
			current.Version--
			current.Avatar = "authorized"
			return struct{}{}, access.users.Update(ctx, current)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := update.Execute(ctx, userSelfInput{ID: user.ID, Profile: svc.UpdateUserRequest{Email: occupied.Email}}); err != nil {
		t.Fatal(err)
	}
	if err := writer.users.Update(ctx, user); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired user writer=%v", err)
	}
	if _, err := writer.email.Read(ctx, occupied.Email); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired email reader=%v", err)
	}
	var stored iamentity.User
	if err := storage.First(&stored, user.ID).Error; err != nil || stored.Avatar != "authorized" || stored.OwnerID != "owner" || stored.Version != 1 {
		t.Fatalf("conditional writer stored=%+v error=%v", &stored, err)
	}
}
