package user

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	ormrepo "gochen-runtime/db/orm/repo"
	"gochen/auth/scoped"
	"gochen/db/orm"
	"gochen/errors"
)

func TestUserRoleBindingProjectionPreservesInvisibleAndDeletedDisclosure(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	base, err := ormrepo.NewRepo[*iamentity.Role, int64](service.roleRepo.Orm(), "roles",
		ormrepo.WithResourceKind[*iamentity.Role, int64](svc.RoleResourceKind),
		ormrepo.WithSoftDeleteColumns[*iamentity.Role, int64]("deleted_at", ""),
		ormrepo.WithIsolation[*iamentity.Role, int64](ormrepo.IsolationCols{Column: "tenant_id"}),
		ormrepo.WithReadPredicate[*iamentity.Role, int64](func(ctx context.Context) (orm.Condition, error) {
			scope, ok := scoped.DataScopeFromContext(ctx)
			if ok && scope.Kind == scoped.ScopeFiltered {
				return orm.Condition{Expr: "namespace_scope_id IN ?", Args: []any{scope.ScopeIDs}}, nil
			}
			return orm.Condition{}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	service.roleRepo.Repo = base
	if err := service.compileRoleBindingReads(); err != nil {
		t.Fatal(err)
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "projection", Email: "projection@example.test"}
	user.ID = 99
	visible := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 1, OwnerID: "owner", Name: "Visible", Code: "visible", Permissions: []string{"user:api:read"}}
	visible.ID = 100
	invisible := &iamentity.Role{TenantID: "tenant-a", NamespaceScopeID: 2, OwnerID: "owner", Name: "Sensitive role", Code: "secret", Permissions: []string{"*:*:*"}}
	invisible.ID = 101
	foreign := &iamentity.Role{TenantID: "tenant-b", NamespaceScopeID: 1, OwnerID: "owner", Name: "Other tenant", Code: "foreign"}
	foreign.ID = 102
	for _, item := range []any{user, visible, invisible, foreign} {
		if err := storage.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []int64{100, 101, 102, 777} {
		if err := storage.Create(&iamentity.UserRoleBinding{UserID: 99, RoleID: role, GrantScopeID: 1, Status: "active"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.Create(&iamentity.UserRoleBinding{UserID: 99, RoleID: 888, GrantScopeID: 1, Status: "inactive"}).Error; err != nil {
		t.Fatal(err)
	}
	result, err := service.UserRoleBindings(ctx, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 4 {
		t.Fatalf("active binding count=%d", len(result))
	}
	for _, detail := range result {
		switch detail.RoleID {
		case 100:
			if detail.RoleName != "Visible" || detail.RoleCode != "visible" || detail.NamespaceScopeID != 1 || len(detail.Permissions) != 1 {
				t.Fatalf("visible=%+v", detail)
			}
		case 101:
			if detail.RoleName != "不可见角色 #101" || detail.RoleCode != "" || detail.NamespaceScopeID != 0 || len(detail.Permissions) != 0 {
				t.Fatalf("invisible=%+v", detail)
			}
		case 102, 777:
			if detail.RoleCode != "" || detail.NamespaceScopeID != 0 || len(detail.Permissions) != 0 {
				t.Fatalf("unavailable=%+v", detail)
			}
		}
	}
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UserRoleBindings(ctx, 99); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("outside user scope=%v", err)
	}
}

func TestUserRoleBindingProjectionReturnsTheCompleteActiveSet(t *testing.T) {
	service, storage, ctx := userAssociationCapabilityFixture(t)
	user := &iamentity.User{TenantID: "tenant-a", ManagedScopeID: 1, HomeTenantID: "tenant-a", HomeScopeID: 1, OwnerID: "owner", Username: "complete", Email: "complete@example.test"}
	user.ID = 99
	if err := storage.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	var bindings []iamentity.UserRoleBinding
	for i := int64(1); i <= 1002; i++ {
		bindings = append(bindings, iamentity.UserRoleBinding{UserID: 99, RoleID: i + 100, GrantScopeID: 1, Status: "active"})
	}
	if err := storage.CreateInBatches(&bindings, 100).Error; err != nil {
		t.Fatal(err)
	}
	result, err := service.UserRoleBindings(ctx, 99)
	if err != nil || len(result) != 1002 {
		t.Fatalf("complete set count=%d error=%v", len(result), err)
	}
}
