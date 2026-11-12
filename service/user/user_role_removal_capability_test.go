package user

import (
	"context"
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func removalCapabilityResources(t *testing.T, service *UserService, bindingCondition spec.Spec, deny bool) []app.CommandResource[UserRoleRemovalInput] {
	t.Helper()
	var resources []app.CommandResource[UserRoleRemovalInput]
	for i, target := range []struct {
		name, resource string
		provider       app.IExecutionDescriptorProvider
		kind           auth.Kind
	}{{"user", svc.UserResourceKind, service.userRepo, auth.KindUpdate}, {"role", svc.RoleResourceKind, service.roleRepo.Repo, auth.KindRead}} {
		authorizer, err := service.authorizer.Compile(auth.Descriptor{Resource: target.resource, Actions: []auth.Action{{Name: "remove_role_" + target.name, Kind: target.kind, Permission: "user:api:write"}}},
			target.provider.ExecutionDescriptor().Metadata(), userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+1))})
		if err != nil {
			t.Fatal(err)
		}
		id := int64(i + 99)
		resources = append(resources, app.CommandResource[UserRoleRemovalInput]{Name: target.name, Repository: target.provider, Authorizer: authorizer, Action: "remove_role_" + target.name,
			Intent: func(UserRoleRemovalInput) (auth.Request, error) {
				return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
			}})
	}
	authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.role_removal.binding", Actions: []auth.Action{{Name: "remove_role_binding", Kind: auth.KindDelete, Permission: "user:api:write"}}}, ResourceAccess: auth.ResourceAccessData,
		Rules: []auth.Rule{{ID: "binding", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{userBindingCondition{condition: bindingCondition, deny: deny}}}}},
		auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: service.roleBindingSource.ExecutionDescriptor().Metadata()})
	if err != nil {
		t.Fatal(err)
	}
	return append(resources, app.CommandResource[UserRoleRemovalInput]{Name: "binding", Repository: service.roleBindingSource, Authorizer: authorizer, Action: "remove_role_binding",
		Intent: func(UserRoleRemovalInput) (auth.Request, error) { return auth.Request{}, nil }})
}

func TestUserRoleRemovalCapabilitiesKeepConditionsSourcesAndLifecycle(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Global())
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "removal", Email: "removal@example.test"}
	user.ID = 99
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 2, OwnerID: "owner", Name: "removal", Status: "inactive"}
	role.ID = 100
	for _, item := range []any{user, role, &iamentity.UserRoleBinding{UserID: 99, RoleID: 100, GrantScopeID: 999, Status: "inactive"}} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	var captured *userRoleRemovalAccess
	command, err := app.NewCommand(app.CommandOptions[UserRoleRemovalInput, *userRoleRemovalAccess, struct{}]{Resources: removalCapabilityResources(t, service, spec.All(), false),
		Access: func(ctx context.Context, in UserRoleRemovalInput, grants []*app.CommandGrant) (*userRoleRemovalAccess, error) {
			if _, err := service.bindRoleRemoval(ctx, "remove_role", in, grants[:2]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing binding=%v", err)
			}
			if _, err := service.bindRoleRemoval(ctx, "http_remove_role", in, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong action=%v", err)
			}
			if _, err := service.bindRoleRemoval(ctx, "remove_role", UserRoleRemovalInput{UserID: 98, RoleID: 100}, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong user=%v", err)
			}
			impostor := &userRoleBindingSource{repository: service.userRepo, execution: service.roleBindingSource.execution}
			if _, err := app.NewCommandWriter(impostor, grants[2], func(context.Context, struct{}, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong actual source=%v", err)
			}
			return service.bindRoleRemoval(ctx, "remove_role", in, grants)
		},
		Handler: func(ctx context.Context, in UserRoleRemovalInput, a *userRoleRemovalAccess) (struct{}, error) {
			captured = a
			if _, err := a.write.Write(ctx, userRoleRemovalSnapshot{}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("untrusted snapshot=%v", err)
			}
			user, err := a.users.Get(ctx, in.UserID)
			if err != nil {
				return struct{}{}, err
			}
			role, err := a.roles.Get(ctx, in.RoleID)
			if err != nil {
				return struct{}{}, err
			}
			a.loaded = &userRoleRemovalSnapshot{User: userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID}, Role: userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID}}
			forged := *a.loaded
			forged.Role.ID = 101
			if _, err := a.write.Write(ctx, forged); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("forged role=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := a.write.Write(other, *a.loaded); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			return a.write.Write(ctx, *a.loaded)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, UserRoleRemovalInput{UserID: 99, RoleID: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := captured.write.Write(ctx, *captured.loaded); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained writer=%v", err)
	}
	var count int64
	if err := storage.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("binding count=%d error=%v", count, err)
	}
	for _, test := range []struct {
		condition spec.Spec
		deny      bool
	}{{spec.Eq(meta.ByField("GrantScopeID"), int64(999)), false}, {spec.All(), true}} {
		if err := storage.Create(&iamentity.UserRoleBinding{UserID: 99, RoleID: 100, GrantScopeID: 999, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
		command, err := app.NewCommand(app.CommandOptions[UserRoleRemovalInput, *userRoleRemovalAccess, struct{}]{Resources: removalCapabilityResources(t, service, test.condition, test.deny),
			Access: func(ctx context.Context, in UserRoleRemovalInput, grants []*app.CommandGrant) (*userRoleRemovalAccess, error) {
				return service.bindRoleRemoval(ctx, "remove_role", in, grants)
			},
			Handler: func(ctx context.Context, _ UserRoleRemovalInput, a *userRoleRemovalAccess) (struct{}, error) {
				return a.binding.Read(ctx, struct{}{})
			}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := command.Execute(ctx, UserRoleRemovalInput{UserID: 99, RoleID: 100}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("incomplete/denied binding=%v", err)
		}
		if err := storage.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("denied removal count=%d error=%v", count, err)
		}
		if err := storage.Where("user_id=99").Delete(&iamentity.UserRoleBinding{}).Error; err != nil {
			t.Fatal(err)
		}
	}
}
