package user

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	hostauthz "gochen-runtime/host/authz"
	"gochen/app"
	appcrud "gochen/app/crud"
	"gochen/auth"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserHTTPExistingOnePrimaryDecision(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"*:*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	item := &iamentity.User{TenantID: "tenant-a", HomeTenantID: "tenant-a", HomeScopeID: 1, ManagedScopeID: 1, OwnerID: "owner", Username: "once", Email: "once@example.test", Password: "existing-password", Status: "active"}
	item.ID = 99
	if err := storage.Create(item).Error; err != nil {
		t.Fatal(err)
	}
	a := *service.httpExisting
	a.resources = map[string][]app.CommandResource[[]int64]{}
	decisions := 0
	for action, resources := range service.httpExisting.resources {
		a.resources[action] = append([]app.CommandResource[[]int64](nil), resources...)
	}
	descriptor, err := appcrud.Describe(a.options, true)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := service.authorizer.Compile(descriptor, service.userRepo.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{}, auth.PolicyFunc(func(context.Context, auth.Request) (auth.Decision, error) {
		decisions++
		return auth.Decision{Allowed: true, Spec: spec.All()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	a.options.Authorizer = compiled
	for action := range a.resources {
		a.resources[action][0].Authorizer = compiled
	}
	service.httpExisting = &a
	result, err := service.ExecuteHTTP(ctx, appcrud.ActionUpdate, item.ID, func(_ context.Context, user *iamentity.User) error {
		user.Password = ""
		user.Avatar = "first"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if decisions != 1 || result.Version != 1 || result.Password != "existing-password" {
		t.Fatalf("decisions=%d result=%+v", decisions, result)
	}
	decisions = 0
	result.Password, result.Avatar = "", "second"
	if err := service.UpdateHTTP(ctx, result); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 || result.Version != 2 || result.Password != "existing-password" {
		t.Fatalf("decisions=%d result=%+v", decisions, result)
	}
	stale, err := meta.Clone(item)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateHTTP(ctx, stale); !errors.Is(err, errors.Concurrency) {
		t.Fatalf("stale update=%v", err)
	}
	decisions = 0
	if _, err := service.ExecuteBulkHTTP(ctx, appcrud.ActionUpdate, []int64{item.ID}, func(_ context.Context, user *iamentity.User) error {
		user.Password = ""
		user.Avatar = "bulk"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 {
		t.Fatalf("bulk primary decisions=%d", decisions)
	}
	decisions = 0
	if err := service.DeleteHTTP(ctx, item.ID); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 {
		t.Fatalf("delete primary decisions=%d", decisions)
	}
}
