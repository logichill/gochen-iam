package role

import (
	"context"
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	rolerepo "gochen-iam/repo/role"
	svc "gochen-iam/service"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/contextx"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gochen/testkit"
)

func TestRoleWriteCapabilitiesKeepConditionSourceTargetIdentityAndLifetime(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	first := env.createTestRole(t, "first")
	second := env.createTestRole(t, "second")
	ctx := roleWritePrincipal(t, env, "7", "tenant", "role:api:write")
	target, err := auth.NewFact("test.role.write_target", func(ctx context.Context, req auth.Request) (*iamentity.Role, error) {
		id, err := strconv.ParseInt(req.IDs[0], 10, 64)
		if err != nil {
			return nil, err
		}
		return env.roleRepo.Get(ctx, id, spec.All())
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := env.roleService.authorizer.Compile(auth.Descriptor{Resource: svc.RoleResourceKind,
		Actions: []auth.Action{{Name: "deactivate", Kind: auth.KindUpdate, Permission: "role:api:write"}}}, env.roleRepo.ExecutionDescriptor().Metadata(),
		roleWriteTargetPolicy{target}, roleStatisticsConditionPolicy{condition: spec.In(meta.ID(), first.ID)})
	if err != nil {
		t.Fatal(err)
	}
	resources := []app.CommandResource[RoleWriteInput]{{Name: "role", Repository: env.roleRepo, Authorizer: authorizer, Action: "deactivate",
		Intent: func(in RoleWriteInput) (auth.Request, error) {
			return auth.Request{IDs: []string{strconv.FormatInt(in.ID, 10)}}, nil
		}}}
	other, err := rolerepo.NewRoleRepository(env.roleRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	var retained *app.CommandRepository[*iamentity.Role, int64]
	command, err := app.NewCommand(app.CommandOptions[RoleWriteInput, *app.CommandRepository[*iamentity.Role, int64], struct{}]{Resources: resources,
		Access: func(_ context.Context, in RoleWriteInput, grants []*app.CommandGrant) (*app.CommandRepository[*iamentity.Role, int64], error) {
			if _, err := env.roleService.bindWrite("deactivate", in, nil); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grants=%v", err)
			}
			if _, err := env.roleService.bindWrite("activate", in, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed operation=%v", err)
			}
			if _, err := env.roleService.bindWrite("deactivate", RoleWriteInput{ID: in.ID + 100}, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed target=%v", err)
			}
			changed := *env.roleService
			changed.roleRepo = other
			if _, err := changed.bindWrite("deactivate", in, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("changed provider=%v", err)
			}
			return env.roleService.bindWrite("deactivate", in, grants)
		},
		Handler: func(ctx context.Context, in RoleWriteInput, roles *app.CommandRepository[*iamentity.Role, int64]) (struct{}, error) {
			retained = roles
			role, err := roles.FromFact(ctx, target)
			if err != nil {
				return struct{}{}, err
			}
			if _, err := roles.Get(ctx, in.ID+100); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("other read ID=%v", err)
			}
			changed, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"role:api:write"}})
			if err != nil {
				return struct{}{}, err
			}
			if err := roles.Update(changed, role); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			changed, err = contextx.WithTenantID(ctx, "other")
			if err != nil {
				return struct{}{}, err
			}
			if _, err := roles.Get(changed, in.ID); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed tenant=%v", err)
			}
			role.OwnerID = "forged"
			if err := roles.Update(ctx, role); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed ownership=%v", err)
			}
			role.OwnerID = first.OwnerID
			role.Version++
			if err := roles.Update(ctx, role); !errors.Is(err, errors.Concurrency) {
				t.Fatalf("changed snapshot version=%v", err)
			}
			role.Version--
			role.Deactivate()
			return struct{}{}, roles.Update(ctx, role)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, RoleWriteInput{ID: first.ID}); err != nil {
		t.Fatal(err)
	}
	if err := retained.Update(ctx, first); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired writer=%v", err)
	}
	if _, err := retained.Get(ctx, first.ID); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired reader=%v", err)
	}
	if _, err := command.Execute(ctx, RoleWriteInput{ID: second.ID}); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("independent condition ignored=%v", err)
	}
	// Construction freezes the actual service provider consumed by production commands.
	env.roleService.roleRepo = nil
	if err := env.roleService.ActivateRole(env.backgroundCtx, first.ID); err != nil {
		t.Fatalf("constructed provider drifted=%v", err)
	}
}
