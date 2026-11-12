package router

import (
	"testing"

	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	tenantsvc "gochen-iam/service/tenant"
	"gochen/testkit"
	"gorm.io/gorm"
)

func tenantRoutesFixture(t *testing.T) (*TenantRoutes, *gorm.DB) {
	t.Helper()
	_, storage, scopes := scopeRoutesFixture(t)
	engine := scopes.Orm()
	tenants, err := tenantrepo.NewTenantRepository(engine, testkit.NewInt64Sequence(100))
	if err != nil {
		t.Fatal(err)
	}
	users, err := userrepo.NewUserRepository(engine, testkit.NewInt64Sequence(100))
	if err != nil {
		t.Fatal(err)
	}
	groups, err := grouprepo.NewGroupRepository(engine, testkit.NewInt64Sequence(100))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := rolerepo.NewRoleRepository(engine, testkit.NewInt64Sequence(100))
	if err != nil {
		t.Fatal(err)
	}
	scopeAuthorizer := svc.NewScopeAuthorizer(scopes, tenants)
	authorizer := svc.NewIAMAccess(scopeAuthorizer)
	service, err := tenantsvc.NewTenantService(tenants, scopeAuthorizer, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewTenantRoutes(service, tenants, scopeAuthorizer, authorizer, users, groups, roles, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return routes, storage
}
