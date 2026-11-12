package user

import (
	"context"
	"strconv"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserGroupWriteCapabilitiesKeepIndependentConditionsAndBoundaries(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "primary", Email: "primary@example.test"}
	user.ID = 99
	group := &iamentity.Group{TenantID: "tenant-a", ManagedScopeID: 2, OwnerID: "owner", Name: "target"}
	group.ID = 100
	for _, item := range []any{user, group} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	var resources []app.CommandResource[UserGroupWriteInput]
	for i, target := range []struct {
		name, resource, action string
		provider               app.IExecutionDescriptorProvider
		kind                   auth.Kind
	}{{"user", svc.UserResourceKind, "assign_group", service.userRepo, auth.KindUpdate}, {"group", svc.GroupResourceKind, "assign_group_group", service.groupRepo, auth.KindRead}} {
		authorizer, err := service.authorizer.Compile(auth.Descriptor{Resource: target.resource,
			Actions: []auth.Action{{Name: target.action, Kind: target.kind, Permission: "user:api:write"}}}, target.provider.ExecutionDescriptor().Metadata(),
			userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(i+1))})
		if err != nil {
			t.Fatal(err)
		}
		id := int64(99 + i)
		resources = append(resources, app.CommandResource[UserGroupWriteInput]{Name: target.name, Repository: target.provider, Authorizer: authorizer, Action: target.action,
			Intent: func(UserGroupWriteInput) (auth.Request, error) {
				return auth.Request{IDs: []string{strconv.FormatInt(id, 10)}}, nil
			}})
	}
	var captured *userGroupWriteAccess
	command, err := app.NewCommand(app.CommandOptions[UserGroupWriteInput, *userGroupWriteAccess, struct{}]{Resources: resources,
		Access: func(_ context.Context, in UserGroupWriteInput, grants []*app.CommandGrant) (*userGroupWriteAccess, error) {
			if _, err := service.bindGroupWrite("assign_group", in, grants[:1]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("missing grant=%v", err)
			}
			if _, err := service.bindGroupWrite("remove_group", in, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong action=%v", err)
			}
			if _, err := service.bindGroupWrite("assign_group", UserGroupWriteInput{UserID: 98, GroupID: 100}, grants); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong input=%v", err)
			}
			impostor, err := ormrepo.NewRepo[*iamentity.Group, int64](service.groupRepo.Orm(), "groups", ormrepo.WithResourceKind[*iamentity.Group, int64](svc.GroupResourceKind), ormrepo.WithIsolation[*iamentity.Group, int64](ormrepo.IsolationCols{Column: "tenant_id"}))
			if err != nil {
				return nil, err
			}
			if _, err := app.NewCommandRepository(impostor, grants[1]); !errors.Is(err, errors.InvalidInput) {
				t.Fatalf("wrong provider=%v", err)
			}
			return service.bindGroupWrite("assign_group", in, grants)
		},
		Handler: func(ctx context.Context, in UserGroupWriteInput, access *userGroupWriteAccess) (struct{}, error) {
			captured = access
			if _, err := access.write.Write(ctx, userGroupWrite{}); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("untrusted snapshot=%v", err)
			}
			user, err := access.users.Get(ctx, in.UserID)
			if err != nil {
				return struct{}{}, err
			}
			group, err := access.groups.Get(ctx, in.GroupID)
			if err != nil {
				return struct{}{}, err
			}
			access.loaded = &userGroupWrite{
				User:  userGroupTarget{user.ID, user.ManagedScopeID, user.Version, user.TenantID, user.OwnerID},
				Group: userGroupTarget{group.ID, group.ManagedScopeID, group.Version, group.TenantID, group.OwnerID},
			}
			forged := *access.loaded
			forged.Group.ScopeID = 1
			if _, err := access.write.Write(ctx, forged); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("forged group=%v", err)
			}
			other, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "8", ActiveScopeID: 1, Permissions: []string{"user:api:write"}})
			if err != nil {
				return struct{}{}, err
			}
			if _, err := access.write.Write(other, *access.loaded); !errors.Is(err, errors.Forbidden) {
				t.Fatalf("changed identity=%v", err)
			}
			// Runtime Lite supports the condition and transaction path; association
			// writes are verified separately with the existing GORM test adapter.
			if _, err := access.write.Write(ctx, *access.loaded); !errors.Is(err, errors.Unsupported) {
				t.Fatalf("independent conditions did not reach the association adapter=%v", err)
			}
			if err := storage.Model(group).UpdateColumn("version", 1).Error; err != nil {
				return struct{}{}, err
			}
			if _, err := access.write.Write(ctx, *access.loaded); !errors.Is(err, errors.Conflict) {
				t.Fatalf("changed snapshot=%v", err)
			}
			return struct{}{}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command.Execute(ctx, UserGroupWriteInput{UserID: 99, GroupID: 100}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := storage.Table("user_groups").Where("user_id = 99 AND group_id = 100").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("independent conditions association count=%d error=%v", count, err)
	}
	if _, err := captured.write.Write(ctx, *captured.loaded); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired writer=%v", err)
	}
	if _, err := captured.groups.Get(ctx, 100); !errors.Is(err, errors.FailedPrecondition) {
		t.Fatalf("expired reader=%v", err)
	}
}
