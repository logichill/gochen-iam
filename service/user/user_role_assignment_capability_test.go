package user

import (
	"context"
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

type userBindingCondition struct {
	condition spec.Spec
	deny      bool
}

func (userBindingCondition) Vocabulary() auth.Vocabulary {
	return auth.Vocabulary{Refs: []meta.Ref{meta.ByField("GrantScopeID")}}
}
func (p userBindingCondition) Evaluate(context.Context, auth.Request) (auth.Decision, error) {
	return auth.Decision{Allowed: !p.deny, Spec: p.condition}, nil
}

func assignmentCapabilityResources(t *testing.T, service *UserService, bindingCondition spec.Spec, deny bool) []app.CommandResource[UserRoleAssignmentInput] {
	t.Helper()
	var resources []app.CommandResource[UserRoleAssignmentInput]
	for i, target := range []struct {
		name, resource string
		provider       app.IExecutionDescriptorProvider
		kind           auth.Kind
	}{{"user", svc.UserResourceKind, service.userRepo, auth.KindUpdate}, {"role", svc.RoleResourceKind, service.roleRepo.Repo, auth.KindRead}} {
		authorizer, err := service.authorizer.Compile(auth.Descriptor{Resource: target.resource,
			Actions: []auth.Action{{Name: "assign_role_" + target.name, Kind: target.kind, Permission: "user:api:write"}}}, target.provider.ExecutionDescriptor().Metadata(),
			userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+1))})
		if err != nil {
			t.Fatal(err)
		}
		id := int64(i + 99)
		resources = append(resources, app.CommandResource[UserRoleAssignmentInput]{Name: target.name, Repository: target.provider, Authorizer: authorizer, Action: "assign_role_" + target.name,
			Intent: func(UserRoleAssignmentInput) (auth.Request, error) {
				return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
			}})
	}
	authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: "iam.user.role_assignment.binding", Actions: []auth.Action{{Name: "assign_role_binding", Kind: auth.KindCreate, Permission: "user:api:write"}}}, ResourceAccess: auth.ResourceAccessData,
		Rules: []auth.Rule{{ID: "binding", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{userBindingCondition{condition: bindingCondition, deny: deny}}}}},
		auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: service.roleBindingSource.ExecutionDescriptor().Metadata()})
	if err != nil {
		t.Fatal(err)
	}
	return append(resources, app.CommandResource[UserRoleAssignmentInput]{Name: "binding", Repository: service.roleBindingSource, Authorizer: authorizer, Action: "assign_role_binding",
		Intent: func(UserRoleAssignmentInput) (auth.Request, error) { return auth.Request{}, nil }})
}

func TestUserRoleAssignmentCapabilitiesKeepIndependentConditionsAndLifecycle(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Global())
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "assignment", Email: "assignment@example.test"}
	user.ID = 99
	role := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 2, OwnerID: "owner", Name: "assignment", Status: "active"}
	role.ID = 100
	for _, item := range []any{user, role} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	var captured *userRoleAssignmentAccess
	command, err := app.NewCommand(app.CommandOptions[UserRoleAssignmentInput, *userRoleAssignmentAccess, struct{}]{Resources: assignmentCapabilityResources(t, service, spec.All(), false),
		Access: func(ctx context.Context, in UserRoleAssignmentInput, grants []*app.CommandGrant) (*userRoleAssignmentAccess, error) {
			if _, err := service.bindRoleAssignment(ctx, "assign_role", in, grants[:2]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing binding=%v", err)
			}
			if _, err := service.bindRoleAssignment(ctx, "http_assign_role", in, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong action=%v", err)
			}
			if _, err := service.bindRoleAssignment(ctx, "assign_role", UserRoleAssignmentInput{UserID: 98, RoleID: 100}, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong user=%v", err)
			}
			impostor := &userRoleBindingSource{repository: service.userRepo, execution: service.roleBindingSource.execution}
			if _, err := app.NewCommandWriter(impostor, grants[2], func(context.Context, struct{}, spec.Spec) (struct{}, error) { return struct{}{}, nil }); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("different binding source=%v", err)
			}
			return service.bindRoleAssignment(ctx, "assign_role", in, grants)
		},
		Handler: func(ctx context.Context, in UserRoleAssignmentInput, access *userRoleAssignmentAccess) (struct{}, error) {
			captured = access
			if _, err := access.write.Write(ctx, userRoleAssignmentSnapshot{}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("untrusted assignment=%v", err)
			}
			user, err := access.users.Get(ctx, in.UserID)
			if err != nil {
				return struct{}{}, err
			}
			role, err := access.roles.Get(ctx, in.RoleID)
			if err != nil {
				return struct{}{}, err
			}
			access.trustedRole = role
			access.loaded = &userRoleAssignmentSnapshot{User: userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID}, Role: userGroupTarget{role.ID, role.NamespaceScopeID, role.Version, role.TenantID, role.OwnerID}, ScopeID: *in.GrantScopeID, RoleStatus: role.Status}
			forged := *access.loaded
			forged.ScopeID = 4
			if _, err := access.write.Write(ctx, forged); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("forged scope=%v", err)
			}
			original := *access.loaded
			access.loaded.ScopeID = 4
			if _, err := access.write.Write(ctx, *access.loaded); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed snapshot escaped the requested grant=%v", err)
			}
			*access.loaded = original
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.write.Write(other, *access.loaded); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			return access.write.Write(ctx, *access.loaded)
		}})
	if err != nil {
		t.Fatal(err)
	}
	scopeID := int64(3)
	if _, err := command.Execute(ctx, UserRoleAssignmentInput{UserID: user.ID, RoleID: role.ID, GrantScopeID: &scopeID}); err != nil {
		t.Fatal(err)
	}
	var binding iamentity.UserRoleBinding
	if err := storage.First(&binding).Error; err != nil || binding.UserID != user.ID || binding.RoleID != role.ID || binding.GrantScopeID != scopeID {
		t.Fatalf("independent condition binding=%+v error=%v", binding, err)
	}
	if _, err := captured.write.Write(ctx, *captured.loaded); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired binding capability=%v", err)
	}
	if _, err := captured.roles.Get(ctx, role.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired role capability=%v", err)
	}
	single := iamtenant.WithPolicy(ctx, iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: "tenant-a"})
	if err := service.AssignRoleBinding(single, user.ID, role.ID, &scopeID); !errors.Is(err, errors.Dependency) {
		t.Fatalf("single assignment without actual scope provider=%v", err)
	}
	for _, denial := range []bool{false, true} {
		entered := false
		command, err := app.NewCommand(app.CommandOptions[UserRoleAssignmentInput, *userRoleAssignmentAccess, struct{}]{Resources: assignmentCapabilityResources(t, service, spec.Eq(meta.ByField("GrantScopeID"), int64(3)), denial),
			Access: func(ctx context.Context, in UserRoleAssignmentInput, grants []*app.CommandGrant) (*userRoleAssignmentAccess, error) {
				return service.bindRoleAssignment(ctx, "assign_role", in, grants)
			},
			Handler: func(ctx context.Context, _ UserRoleAssignmentInput, access *userRoleAssignmentAccess) (struct{}, error) {
				entered = true
				return access.bindingGuard.Read(ctx, struct{}{})
			}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := command.Execute(ctx, UserRoleAssignmentInput{UserID: 99, RoleID: 100}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("partial or denied binding=%v", err)
		}
		if entered == denial {
			t.Fatalf("later grant denial=%v entered handler=%v", denial, entered)
		}
	}
}
