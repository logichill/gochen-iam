package role

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	rolerepo "gochen-iam/repo/role"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestRoleSystemDirectoryCapabilitiesKeepIndependentConditionsAndTrustedSources(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	roles := []*iamentity.Role{}
	for i := 1; i <= 3; i++ {
		scope := &iamentity.Scope{Key: fmt.Sprintf("namespace-%d", i), Type: "tenant", Name: "namespace", Path: fmt.Sprintf("/namespace-%d/", i)}
		scope.ID = int64(i)
		if err := env.db.Create(scope).Error; err != nil {
			t.Fatal(err)
		}
		role := &iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: scope.ID, Name: fmt.Sprintf("role-%d", i), IsSystem: true}
		if err := env.db.Create(role).Error; err != nil {
			t.Fatal(err)
		}
		roles = append(roles, role)
	}
	namespaces, err := ormrepo.NewRepo[*iamentity.Scope, int64](env.roleRepo.Orm(), "scopes",
		ormrepo.WithResourceKind[*iamentity.Scope, int64](roleNamespaceResource),
		ormrepo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""))
	if err != nil {
		t.Fatal(err)
	}
	otherNamespaces, err := ormrepo.NewRepo[*iamentity.Scope, int64](env.roleRepo.Orm(), "scopes",
		ormrepo.WithResourceKind[*iamentity.Scope, int64](roleNamespaceResource))
	if err != nil {
		t.Fatal(err)
	}
	otherRoles, err := rolerepo.NewRoleRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	resources := []app.CommandResource[struct{}]{}
	for i, name := range []string{"roles", "namespaces"} {
		var provider app.IExecutionDescriptorProvider = env.roleRepo.Repo
		resource, action := svc.RoleResourceKind, "system_roles"
		condition := spec.In(meta.ID(), roles[0].ID, roles[1].ID)
		if i == 1 {
			provider, resource, action = namespaces, roleNamespaceResource, "system_roles_namespace"
			condition = spec.In(meta.ID(), int64(2))
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource,
			Actions: []auth.Action{{Name: action, Kind: auth.KindList, Permission: "role:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
			Rules: []auth.Rule{{ID: "test.role.system", System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{roleStatisticsConditionPolicy{condition: condition}}}}},
			auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: provider.ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[struct{}]{Name: name, Repository: provider, Authorizer: authorizer, Action: action,
			Intent: func(struct{}) (auth.Request, error) { return auth.Request{}, nil }})
	}
	ctx := roleStatisticsPrincipal(t, env.tenantID, "7", "tenant", "role:api:read")
	var retained *roleSystemAccess
	command, err := app.NewCommand(app.CommandOptions[struct{}, *roleSystemAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, _ struct{}, grants []*app.CommandGrant) (*roleSystemAccess, error) {
			if _, err := env.roleService.bindSystemAccess("system_roles", namespaces, nil); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grants=%v", err)
			}
			if _, err := env.roleService.bindSystemAccess("http_system_roles", namespaces, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed action=%v", err)
			}
			if _, err := env.roleService.bindSystemAccess("system_roles", otherNamespaces, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed namespace provider=%v", err)
			}
			changed := *env.roleService
			changed.roleRepo = otherRoles
			if _, err := changed.bindSystemAccess("system_roles", namespaces, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed role provider=%v", err)
			}
			return env.roleService.bindSystemAccess("system_roles", namespaces, grants)
		}, Handler: func(ctx context.Context, _ struct{}, access *roleSystemAccess) (struct{}, error) {
			retained = access
			if _, err := access.namespaces.Read(ctx, []int64{2}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("namespace before role source=%v", err)
			}
			result, err := access.roles.Read(ctx, struct{}{})
			if err != nil {
				return struct{}{}, err
			}
			if len(result) != 2 {
				t.Fatalf("role condition ignored=%+v", result)
			}
			scopes, err := access.namespaces.Read(ctx, []int64{1, 2, 2})
			if err != nil {
				return struct{}{}, err
			}
			if len(scopes) != 1 || scopes[0].ID != 2 {
				t.Fatalf("namespace condition ignored=%+v", scopes)
			}
			if _, err := access.namespaces.Read(ctx, []int64{3}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("namespace of excluded role=%v", err)
			}
			changed, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"role:api:read"}})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.namespaces.Read(changed, []int64{2}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			changed, err = contextx.WithTenantID(ctx, "other")
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.roles.Read(changed, struct{}{}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed tenant=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.roles.Read(ctx, struct{}{}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired role reader=%v", err)
	}
	if _, err := retained.namespaces.Read(ctx, []int64{2}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired namespace reader=%v", err)
	}
	denied, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: roleNamespaceResource,
		Actions: []auth.Action{{Name: "system_roles_namespace", Kind: auth.KindList, Permission: "role:api:read"}}}, ResourceAccess: auth.ResourceAccessData,
		Rules: []auth.Rule{{ID: "test.role.system.deny", Constraints: []auth.IPolicy{roleStatisticsConditionPolicy{deny: true}}}}},
		auth.CompileOptions{Checker: hostauthz.NewActionChecker(), Metadata: namespaces.ExecutionDescriptor().Metadata()})
	if err != nil {
		t.Fatal(err)
	}
	resources[1].Authorizer = denied
	accessCalled := false
	deniedCommand, err := app.NewCommand(app.CommandOptions[struct{}, *roleSystemAccess, struct{}]{Resources: resources,
		Access: func(context.Context, struct{}, []*app.CommandGrant) (*roleSystemAccess, error) {
			accessCalled = true
			return nil, nil
		},
		Handler: func(context.Context, struct{}, *roleSystemAccess) (struct{}, error) {
			t.Fatal("denied handler ran")
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	reads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("role:system:later_denial", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if _, err := deniedCommand.Execute(ctx, struct{}{}); !errors.Is(err, errors.Forbidden) || accessCalled || reads.Load() != 0 {
		t.Fatalf("later denial=%v access called=%v reads=%d", err, accessCalled, reads.Load())
	}
}
