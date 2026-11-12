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
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func bindingReadCapabilityResources(t *testing.T, s *UserService, bindingCondition, roleCondition spec.Spec, denyRole bool) ([]app.CommandResource[int64], *auth.Fact[*iamentity.User]) {
	t.Helper()
	target, err := auth.NewFact("test.binding_read.user", func(ctx context.Context, req auth.Request) (*iamentity.User, error) {
		id, err := userGroupFactID(req, svc.UserResourceKind)
		if err != nil {
			return nil, err
		}
		return s.userRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := s.authorizer.Compile(auth.Descriptor{Resource: svc.UserResourceKind, Actions: []auth.Action{{Name: "role_bindings_user", Kind: auth.KindRead, Permission: "user:api:read"}}}, s.userRepo.ExecutionDescriptor().Metadata(),
		userStatusTargetPolicy{target}, userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(1))})
	if err != nil {
		t.Fatal(err)
	}
	resources := []app.CommandResource[int64]{{Name: "user", Repository: s.userRepo, Authorizer: users, Action: "role_bindings_user",
		Intent: func(id int64) (auth.Request, error) {
			return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
		}}}
	for _, name := range []string{"binding", "role"} {
		provider := app.IExecutionDescriptorProvider(s.roleBindingSource)
		policy := auth.IPolicy(userBindingCondition{condition: bindingCondition})
		if name == "role" {
			provider = s.roleRepo.Repo
			policy = userAssociationCondition{condition: roleCondition, deny: denyRole}
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.binding_projection." + name, Actions: []auth.Action{{Name: "role_bindings_" + name, Kind: auth.KindRead, Permission: "user:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "projection", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{policy}}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: "role_bindings_" + name, Intent: func(int64) (auth.Request, error) { return auth.Request{}, nil }})
	}
	return resources, target
}

func TestUserRoleBindingReadCapabilitiesKeepTrustedRelationsAndLifecycle(t *testing.T) {
	s, storage, ctx := userAssociationCapabilityFixture(t)
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "binding-capability", Email: "binding-capability@example.test"}
	user.ID = 99
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 2, OwnerID: "owner", Name: "Binding role", Code: "binding", Permissions: []string{"user:api:read"}}
	role.ID = 100
	binding := &iamentity.UserRoleBinding{UserID: 99, RoleID: 100, GrantScopeID: 1, Status: "active"}
	for _, item := range []any{user, role, binding} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	resources, target := bindingReadCapabilityResources(t, s, spec.All(), spec.All(), false)
	var captured *userRoleBindingReadAccess
	var selected userrepo.BindingRecord
	command, err := app.NewCommand(app.CommandOptions[int64, *userRoleBindingReadAccess, []*svc.UserRoleBindingDetail]{Resources: resources,
		Access: func(ctx context.Context, id int64, grants []*app.CommandGrant) (*userRoleBindingReadAccess, error) {
			if _, err := s.bindRoleBindingRead(ctx, "role_bindings", id, target, grants[:2]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing role=%v", err)
			}
			if _, err := s.bindRoleBindingRead(ctx, "http_role_bindings", id, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong action=%v", err)
			}
			if _, err := s.bindRoleBindingRead(ctx, "role_bindings", id+1, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong target=%v", err)
			}
			impostor := &userRoleBindingSource{repository: s.userRepo, execution: s.roleBindingSource.execution}
			if _, err := app.NewCommandReader(impostor, grants[1], func(context.Context, struct{}, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong binding provider=%v", err)
			}
			return s.bindRoleBindingRead(ctx, "role_bindings", id, target, grants)
		},
		Handler: func(ctx context.Context, id int64, a *userRoleBindingReadAccess) ([]*svc.UserRoleBindingDetail, error) {
			captured = a
			if _, err := a.bindings.Read(ctx, id+1); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("wrong user source=%v", err)
			}
			bindings, err := a.bindings.Read(ctx, id)
			if err != nil {
				return nil, err
			}
			if len(bindings) != 1 {
				t.Fatalf("bindings=%+v", bindings)
			}
			selected = bindings[0]
			forged := selected
			forged.RoleID = 101
			if _, err := a.roles.Read(ctx, forged); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("forged relation=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:read"}})
			if err != nil {
				return nil, err
			}
			if _, err := a.roles.Read(other, selected); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			projection, err := a.roles.Read(ctx, selected)
			if err != nil {
				return nil, err
			}
			projection.Role.Permissions[0] = "forged:api:write"
			return executeRoleBindingRead(ctx, id, a)
		}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := command.Execute(ctx, 99)
	if err != nil || len(result) != 1 || result[0].RoleName != "Binding role" || len(result[0].Permissions) != 1 || result[0].Permissions[0] != "user:api:read" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if _, err := captured.roles.Read(ctx, selected); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained role reader=%v", err)
	}
	if _, err := captured.bindings.Read(ctx, 99); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained binding reader=%v", err)
	}
	for _, test := range []struct {
		binding, role spec.Spec
		deny          bool
	}{
		{spec.Eq(meta.ByField("GrantScopeID"), int64(1)), spec.All(), false},
		{spec.All(), spec.Eq(meta.ByDimension("scope"), int64(2)), false},
		{spec.All(), spec.All(), true},
	} {
		resources, target := bindingReadCapabilityResources(t, s, test.binding, test.role, test.deny)
		entered := false
		command, err := app.NewCommand(app.CommandOptions[int64, *userRoleBindingReadAccess, []*svc.UserRoleBindingDetail]{Resources: resources,
			Access: func(ctx context.Context, id int64, grants []*app.CommandGrant) (*userRoleBindingReadAccess, error) {
				return s.bindRoleBindingRead(ctx, "role_bindings", id, target, grants)
			},
			Handler: func(ctx context.Context, id int64, a *userRoleBindingReadAccess) ([]*svc.UserRoleBindingDetail, error) {
				entered = true
				return executeRoleBindingRead(ctx, id, a)
			}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := command.Execute(ctx, 99); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("partial/denied projection=%v", err)
		}
		if test.deny && entered {
			t.Fatal("later role denial entered the handler")
		}
	}
}
