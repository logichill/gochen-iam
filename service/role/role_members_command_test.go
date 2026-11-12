package role

import (
	"context"
	"strings"
	"testing"

	iamentity "gochen-iam/entity"
	rolerepo "gochen-iam/repo/role"
	svc "gochen-iam/service"
	"gochen/app"
	"gochen/auth"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestRoleMemberCommandsRetainScopesAndRealRelations(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	source := env.createTestRole(t, "members-source")
	extra := env.createTestRole(t, "members-extra")
	env.createTestRole(t, "members-unrelated")
	for _, role := range []*iamentity.Role{source, extra} {
		if err := env.db.Model(role).Update("namespace_scope_id", 2).Error; err != nil {
			t.Fatal(err)
		}
	}
	foreign := &iamentity.Role{TenantID: "other", OwnerID: "tenant:other", NamespaceScopeID: 1, Name: "foreign", Code: "foreign", Status: "active"}
	if err := env.db.Create(foreign).Error; err != nil {
		t.Fatal(err)
	}
	users := []*iamentity.User{}
	for index, scope := range []int64{1, 2, 1} {
		tenant := env.tenantID
		if index == 2 {
			tenant = "other"
		}
		name := []string{"visible-member", "hidden-member", "foreign-member"}[index]
		u := &iamentity.User{TenantID: tenant, HomeTenantID: tenant, HomeScopeID: scope, ManagedScopeID: scope, OwnerID: svc.TenantOwnerID(tenant), Username: name, Email: name + "@example.com", Status: "active"}
		if err := env.db.Create(u).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: u.ID, RoleID: source.ID, GrantScopeID: scope, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
		users = append(users, u)
	}
	for _, r := range []*iamentity.Role{extra, foreign} {
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: users[0].ID, RoleID: r.ID, GrantScopeID: 1, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	groups := []*iamentity.Group{}
	for index, scope := range []int64{1, 2, 1} {
		g := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: scope, OwnerID: svc.TenantOwnerID(env.tenantID), Name: []string{"visible-group", "hidden-group", "unrelated-group"}[index]}
		if err := env.db.Create(g).Error; err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g)
		if index < 2 {
			if err := env.db.Exec("INSERT INTO user_groups (user_id,group_id) VALUES (?,?)", users[0].ID, g.ID).Error; err != nil {
				t.Fatal(err)
			}
			if err := env.db.Exec("INSERT INTO group_roles (group_id,role_id) VALUES (?,?)", g.ID, source.ID).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	sourceReads := 0
	if err := env.db.Callback().Query().After("gorm:query").Register("role-members:source-reads", func(db *gorm.DB) {
		if db.Statement.Table == "roles" && strings.HasSuffix(strings.TrimSpace(db.Statement.SQL.String()), "LIMIT 1") {
			sourceReads++
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:read")
	result, err := env.roleService.RoleUsers(ctx, source.ID)
	if err != nil || len(result) != 1 || result[0].ID != users[0].ID {
		t.Fatalf("scoped members=%+v %v", result, err)
	}
	if sourceReads != 1 {
		t.Fatalf("source reads=%d, want 1", sourceReads)
	}
	if len(result[0].Groups) != 1 || result[0].Groups[0].ID != groups[0].ID {
		t.Fatalf("independent group scope=%+v", result[0].Groups)
	}
	if len(result[0].Roles) != 2 {
		t.Fatalf("actual tenant role relations=%+v", result[0].Roles)
	}
	for _, r := range result[0].Roles {
		if r.ID != source.ID && r.ID != extra.ID {
			t.Fatalf("unrelated role=%+v", r)
		}
	}
	denied, err := scoped.WithDataScope(ctx, scoped.DenyAll())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := env.roleService.RoleUsers(denied, source.ID); err != nil || len(result) != 0 {
		t.Fatalf("deny-all members=%+v %v", result, err)
	}
	if _, err := env.roleService.RoleGroups(ctx, source.ID); !errors.Is(err, errors.NotFound) {
		t.Fatalf("source role scope=%v", err)
	}
	if err := env.db.Model(source).Update("namespace_scope_id", 1).Error; err != nil {
		t.Fatal(err)
	}
	projected, err := env.roleService.RoleGroups(ctx, source.ID)
	if err != nil || len(projected) != 1 || projected[0].ID != groups[0].ID {
		t.Fatalf("scoped role groups=%+v %v", projected, err)
	}
	if err := env.db.Model(source).Update("owner_id", "platform").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := env.roleService.RoleGroups(ctx, source.ID); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("platform role ownership=%v", err)
	}
	for action, count := range map[string]int{"users": 3, "groups": 1} {
		binding, err := env.roleService.CustomAuthorizationBinding(action)
		if err != nil || len(binding.Resources) != count {
			t.Fatalf("%s resources=%+v %v", action, binding, err)
		}
	}
}

func TestRoleUsersCapabilitiesConstrainDerivedSourcesConditionsAndLifetime(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	source := env.createTestRole(t, "capability-source")
	extra := env.createTestRole(t, "capability-extra")
	u := &iamentity.User{TenantID: env.tenantID, HomeTenantID: env.tenantID, HomeScopeID: 1, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Username: "capability-member", Email: "capability@example.com", Status: "active"}
	g := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Name: "capability-group"}
	if err := env.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec("INSERT INTO user_groups (user_id,group_id) VALUES (?,?)", u.ID, g.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range []*iamentity.Role{source, extra} {
		if err := env.db.Create(&iamentity.UserRoleBinding{UserID: u.ID, RoleID: r.ID, GrantScopeID: 1, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	reads := 0
	target, err := auth.NewFact("test.role.members", func(ctx context.Context, _ auth.Request) (*iamentity.Role, error) {
		reads++
		return env.roleRepo.Repo.Get(ctx, source.ID, spec.All())
	})
	if err != nil {
		t.Fatal(err)
	}
	resources := []app.CommandResource[int64]{}
	for i, name := range []string{"role", "users", "groups", "member_roles"} {
		provider, resource, action := app.IExecutionDescriptorProvider(env.roleRepo.Repo), svc.RoleResourceKind, "users"
		var policy auth.IPolicy = roleUsersSourcePolicy{service: env.roleService, target: target}
		intent := roleMemberIntent
		if i > 0 {
			action = "users_" + name
			intent = func(int64) (auth.Request, error) { return auth.Request{}, nil }
			switch name {
			case "users":
				provider, resource = env.roleService.userRepo, "iam.role.users_user"
				policy = roleStatisticsConditionPolicy{condition: spec.Eq(meta.ID(), u.ID)}
			case "groups":
				provider, resource = env.roleService.groupRepo, "iam.role.users_group"
				policy = roleStatisticsConditionPolicy{condition: spec.Spec{}}
			case "member_roles":
				policy = roleStatisticsConditionPolicy{condition: spec.Eq(meta.ID(), extra.ID)}
			}
		}
		authorizer, err := auth.Compile(auth.Declaration{Descriptor: auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action, Kind: auth.KindRead, Permission: "role:api:read"}}}, ResourceAccess: auth.ResourceAccessData, Rules: []auth.Rule{{System: auth.SystemCheckConstraints, Constraints: []auth.IPolicy{policy}}}}, auth.CompileOptions{Checker: auth.ActionCheckerFunc(func(context.Context, string) error { return nil }), Metadata: provider.ExecutionDescriptor().Metadata()})
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: action, Intent: intent})
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:read")
	var retained *roleUsersAccess
	command, err := app.NewCommand(app.CommandOptions[int64, *roleUsersAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (*roleUsersAccess, error) {
			if _, err := env.roleService.bindRoleUsers(id+1, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed source intent=%v", err)
			}
			other, err := rolerepo.NewRoleRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
			if err != nil {
				t.Fatal(err)
			}
			changed := *env.roleService
			changed.roleRepo = other
			if _, err := changed.bindRoleUsers(id, target, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed provider=%v", err)
			}
			return env.roleService.bindRoleUsers(id, target, grants)
		}, Handler: func(ctx context.Context, id int64, a *roleUsersAccess) (struct{}, error) {
			retained = a
			if _, err := a.users.Read(ctx, id); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("members before source=%v", err)
			}
			if _, err := a.source.Read(ctx, struct{}{}); err != nil {
				return struct{}{}, err
			}
			if _, err := a.users.Read(ctx, id+1); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed member source=%v", err)
			}
			if _, err := a.groups.Read(ctx, []int64{u.ID}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("nested group before members=%v", err)
			}
			members, err := a.users.Read(ctx, id)
			if err != nil || len(members.Items) != 1 {
				t.Fatalf("member condition=%+v %v", members, err)
			}
			groups, err := a.groups.Read(ctx, []int64{u.ID})
			if err != nil || len(groups.Items) != 0 {
				t.Fatalf("group condition=%+v %v", groups, err)
			}
			roles, err := a.roles.Read(ctx, []int64{u.ID})
			if err != nil || len(roles.Items) != 1 || roles.Items[0].ID != extra.ID {
				t.Fatalf("role condition=%+v %v", roles, err)
			}
			if _, err := a.roles.Read(ctx, []int64{u.ID + 1}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("untrusted nested source=%v", err)
			}
			changed, err := contextx.WithTenantID(ctx, "other")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.users.Read(changed, id); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed tenant=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, source.ID); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("trusted source loads=%d", reads)
	}
	for _, call := range []func() error{
		func() error { _, err := retained.source.Read(ctx, struct{}{}); return err },
		func() error { _, err := retained.users.Read(ctx, source.ID); return err },
		func() error { _, err := retained.groups.Read(ctx, []int64{u.ID}); return err },
		func() error { _, err := retained.roles.Read(ctx, []int64{u.ID}); return err },
	} {
		if err := call(); !errors.Is(err, errors.FailedPrecondition) {
			t.Fatalf("retained capability=%v", err)
		}
	}
}

func TestRoleGroupsCapabilitiesRequireSourceAndRevokeReaders(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	source := env.createTestRole(t, "group-source")
	g := &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), Name: "derived-group"}
	if err := env.db.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Exec("INSERT INTO group_roles (group_id,role_id) VALUES (?,?)", g.ID, source.ID).Error; err != nil {
		t.Fatal(err)
	}
	resources := []app.CommandResource[int64]{}
	for i, name := range []string{"role", "groups"} {
		provider, resource, action := app.IExecutionDescriptorProvider(env.roleRepo.Repo), svc.RoleResourceKind, "groups"
		intent := roleMemberIntent
		if i == 1 {
			provider, resource, action = env.roleService.groupRepo, svc.GroupResourceKind, "groups_groups"
			intent = func(int64) (auth.Request, error) { return auth.Request{}, nil }
		}
		authorizer, err := env.roleService.authorizer.Compile(auth.Descriptor{Resource: resource, Actions: []auth.Action{{Name: action, Kind: auth.KindRead, Permission: "role:api:read"}}}, provider.ExecutionDescriptor().Metadata())
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, app.CommandResource[int64]{Name: name, Repository: provider, Authorizer: authorizer, Action: action, Intent: intent})
	}
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:read")
	var retained *roleGroupsAccess
	command, err := app.NewCommand(app.CommandOptions[int64, *roleGroupsAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, id int64, grants []*app.CommandGrant) (*roleGroupsAccess, error) {
			if _, err := env.roleService.bindRoleGroups(id+1, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed group source=%v", err)
			}
			return env.roleService.bindRoleGroups(id, grants)
		}, Handler: func(ctx context.Context, id int64, a *roleGroupsAccess) (struct{}, error) {
			retained = a
			if _, err := a.groups.Read(ctx, id); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("groups before source=%v", err)
			}
			if _, err := a.source.Read(ctx, struct{}{}); err != nil {
				return struct{}{}, err
			}
			if _, err := a.groups.Read(ctx, id+1); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed relation source=%v", err)
			}
			groups, err := a.groups.Read(ctx, id)
			if err != nil || len(groups.Items) != 1 || groups.Items[0].ID != g.ID {
				t.Fatalf("derived groups=%+v %v", groups, err)
			}
			changed, err := contextx.WithTenantID(ctx, "other")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.groups.Read(changed, id); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed tenant=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.source.Read(ctx, struct{}{}); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained group source=%v", err)
	}
	if _, err := retained.groups.Read(ctx, source.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("retained group reader=%v", err)
	}
}
