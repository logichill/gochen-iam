package user

import (
	"testing"

	iamentity "gochen-iam/entity"
	hostauthz "gochen-runtime/host/authz"
	appcrud "gochen/app/crud"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
)

func TestUserHTTPCreateExecutesFinalAuthorizedCondition(t *testing.T) {
	s, storage, ctx := userAssociationCapabilityFixture(t)
	ctx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: 1, Permissions: []string{"user:api:manage", "user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	options := s.httpExisting.options
	authorizer, err := s.authorizer.Compile(s.httpExisting.core.Descriptor(), s.userRepo.ExecutionDescriptor().Metadata(), userAssociationEntryPolicy{}, userAssociationCondition{condition: spec.Eq(meta.ByDimension("scope"), int64(2))})
	if err != nil {
		t.Fatal(err)
	}
	options.Authorizer = authorizer
	s.httpExisting.core, err = appcrud.NewApplication(s.userRepo, options)
	if err != nil {
		t.Fatal(err)
	}
	item := &iamentity.User{Username: "outside", Email: "outside@example.test", Password: "secret-password"}
	if err := s.CreateHTTP(ctx, item); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("final create condition=%v", err)
	}
	var count int64
	if err := storage.Model(&iamentity.User{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("out-of-condition create count=%d error=%v", count, err)
	}
}
