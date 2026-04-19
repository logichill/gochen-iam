package scope

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	grouprepo "gochen-iam/repo/group"
	rolerepo "gochen-iam/repo/role"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	userrepo "gochen-iam/repo/user"
	svc "gochen-iam/service"
	"gochen/auth"
	"gochen/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type scopeServiceTestEnv struct {
	db              *gorm.DB
	scopeRepo       *scoperepo.ScopeRepo
	tenantRepo      *tenantrepo.TenantRepo
	roleRepo        *rolerepo.RoleRepo
	userRepo        *userrepo.UserRepo
	groupRepo       *grouprepo.GroupRepo
	scopeAuthorizer *svc.ScopeAuthorizer
	scopeService    *ScopeService
	backgroundCtx   context.Context
	cancelFunc      context.CancelFunc
}

func setupScopeServiceTest(t *testing.T) *scopeServiceTestEnv {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "scope_test.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(
		&iamentity.Scope{},
		&iamentity.ScopeVisibility{},
		&iamentity.Tenant{},
		&iamentity.Role{},
		&iamentity.User{},
		&iamentity.Group{},
		&iamentity.UserRoleBinding{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	ormAdapter := newScopeTestOrm(db)
	scopeRepo, err := scoperepo.NewScopeRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewScopeRepository: %v", err)
	}
	tenantRepo, err := tenantrepo.NewTenantRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewTenantRepository: %v", err)
	}
	roleRepo, err := rolerepo.NewRoleRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}
	userRepo, err := userrepo.NewUserRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	groupRepo, err := grouprepo.NewGroupRepository(ormAdapter)
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}
	authzRegistry, err := svc.NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	if _, err := svc.NewIAMAuthorizer(nil, authzRegistry); err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	baseCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	baseCtx, err = auth.WithPrincipal(baseCtx, auth.Principal{
		SubjectID:   1,
		Permissions: []string{"*:*:*"},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}

	scopeAuthorizer := svc.NewScopeAuthorizer(scopeRepo, tenantRepo)
	platformScope, err := scopeAuthorizer.EnsurePlatformScope(baseCtx)
	if err != nil {
		t.Fatalf("EnsurePlatformScope: %v", err)
	}
	ctx := iamauth.BindActiveScopeContext(baseCtx, platformScope.ID, string(iamentity.ScopeTypePlatform))

	return &scopeServiceTestEnv{
		db:              db,
		scopeRepo:       scopeRepo,
		tenantRepo:      tenantRepo,
		roleRepo:        roleRepo,
		userRepo:        userRepo,
		groupRepo:       groupRepo,
		scopeAuthorizer: scopeAuthorizer,
		scopeService:    NewScopeService(scopeRepo, tenantRepo, roleRepo, userRepo, groupRepo, scopeAuthorizer),
		backgroundCtx:   ctx,
		cancelFunc:      cancel,
	}
}

func (env *scopeServiceTestEnv) teardown(t *testing.T) {
	env.cancelFunc()
	sqlDB, err := env.db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

func (env *scopeServiceTestEnv) platformScope(t *testing.T) *iamentity.Scope {
	t.Helper()
	scope, err := env.scopeAuthorizer.EnsurePlatformScope(env.backgroundCtx)
	if err != nil {
		t.Fatalf("EnsurePlatformScope: %v", err)
	}
	return scope
}

func (env *scopeServiceTestEnv) createTenant(t *testing.T, key, name string) (*iamentity.Tenant, *iamentity.Scope) {
	t.Helper()
	tenant := &iamentity.Tenant{
		Key:         key,
		Name:        name,
		Description: name + " desc",
		Status:      svc.TenantStatusInactive,
	}
	guard, err := svc.NewPlatformCreateConstraint(env.backgroundCtx, svc.TenantResourceKind)
	if err != nil {
		t.Fatalf("NewPlatformCreateConstraint: %v", err)
	}
	if err := env.tenantRepo.CreateWithConstraint(env.backgroundCtx, tenant, guard); err != nil {
		t.Fatalf("CreateWithConstraint: %v", err)
	}
	rootScope, err := env.scopeAuthorizer.EnsureTenantRootScope(env.backgroundCtx, tenant)
	if err != nil {
		t.Fatalf("EnsureTenantRootScope: %v", err)
	}
	return tenant, rootScope
}

func TestScopeService_CreateScope_RebuildsVisibilityAndSupportsLifecycle(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)

	created, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:         "cn-east",
		Name:        "华东大区",
		Type:        "region",
		ParentID:    platformScope.ID,
		Description: "platform child scope",
		Status:      iamentity.ScopeStatusInactive,
	})
	if err != nil {
		t.Fatalf("CreateScope: %v", err)
	}
	if created.Type != "region" {
		t.Fatalf("expected custom scope type kept, got %q", created.Type)
	}
	if created.ParentID == nil || *created.ParentID != platformScope.ID {
		t.Fatalf("expected parent %d, got %v", platformScope.ID, created.ParentID)
	}
	if created.Path != "/platform/cn-east/" {
		t.Fatalf("expected path /platform/cn-east/, got %q", created.Path)
	}
	if created.Depth != platformScope.Depth+1 {
		t.Fatalf("expected depth %d, got %d", platformScope.Depth+1, created.Depth)
	}
	if created.Status != iamentity.ScopeStatusInactive {
		t.Fatalf("expected inactive status, got %q", created.Status)
	}

	visibleScopeIDs, err := env.scopeRepo.VisibleScopeIDs(env.backgroundCtx, platformScope.ID)
	if err != nil {
		t.Fatalf("VisibleScopeIDs: %v", err)
	}
	if !containsScopeID(visibleScopeIDs, created.ID) {
		t.Fatalf("expected platform viewer to see created scope, got %v", visibleScopeIDs)
	}

	updated, err := env.scopeService.UpdateScope(env.backgroundCtx, created.ID, &svc.UpdateScopeRequest{
		Name:        "华东一区",
		Description: "updated desc",
		Status:      iamentity.ScopeStatusActive,
	})
	if err != nil {
		t.Fatalf("UpdateScope: %v", err)
	}
	if updated.Name != "华东一区" || updated.Description != "updated desc" || updated.Status != iamentity.ScopeStatusActive {
		t.Fatalf("unexpected updated scope: %+v", updated)
	}

	if err := env.scopeService.DeactivateScope(env.backgroundCtx, created.ID); err != nil {
		t.Fatalf("DeactivateScope: %v", err)
	}
	reloaded, err := env.scopeRepo.Get(env.backgroundCtx, created.ID)
	if err != nil {
		t.Fatalf("reload scope after deactivate: %v", err)
	}
	if reloaded.Status != iamentity.ScopeStatusInactive {
		t.Fatalf("expected inactive after deactivate, got %q", reloaded.Status)
	}

	if err := env.scopeService.ActivateScope(env.backgroundCtx, created.ID); err != nil {
		t.Fatalf("ActivateScope: %v", err)
	}
	reloaded, err = env.scopeRepo.Get(env.backgroundCtx, created.ID)
	if err != nil {
		t.Fatalf("reload scope after activate: %v", err)
	}
	if reloaded.Status != iamentity.ScopeStatusActive {
		t.Fatalf("expected active after activate, got %q", reloaded.Status)
	}
}

func TestScopeService_RejectsProtectedRootMutations(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)
	_, tenantRoot := env.createTenant(t, "acme", "Acme")

	if _, err := env.scopeService.UpdateScope(env.backgroundCtx, platformScope.ID, &svc.UpdateScopeRequest{Name: "Mutated"}); err == nil {
		t.Fatalf("expected platform root update to be rejected")
	} else if !strings.Contains(err.Error(), "platform root scope") {
		t.Fatalf("expected platform root protection error, got %v", err)
	}

	if _, err := env.scopeService.UpdateScope(env.backgroundCtx, tenantRoot.ID, &svc.UpdateScopeRequest{Name: "Mutated"}); err == nil {
		t.Fatalf("expected tenant root update to be rejected")
	} else if !strings.Contains(err.Error(), "tenant root scope") {
		t.Fatalf("expected tenant root protection error, got %v", err)
	}
}

func TestScopeService_CreateScope_RejectsReservedTypes(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)

	for _, tt := range []struct {
		name      string
		scopeType string
		want      string
	}{
		{name: "platform reserved", scopeType: iamentity.ScopeTypePlatform, want: "platform root scope"},
		{name: "tenant reserved", scopeType: iamentity.ScopeTypeTenant, want: "tenant root scope"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
				Key:      "reserved-" + tt.scopeType,
				Name:     "Reserved",
				Type:     tt.scopeType,
				ParentID: platformScope.ID,
			})
			if err == nil {
				t.Fatalf("expected reserved type %q to be rejected", tt.scopeType)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q in error, got %v", tt.want, err)
			}
		})
	}
}

func TestScopeService_CreateScope_DeniesNonPlatformScope(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	_, tenantRoot := env.createTenant(t, "tenant-a", "Tenant A")
	tenantCtx, err := auth.WithPrincipal(context.Background(), auth.Principal{
		SubjectID:   2,
		Permissions: []string{"*:*:*"},
		IsSystem:    true,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	tenantCtx = iamauth.BindActiveScopeContext(tenantCtx, tenantRoot.ID, string(iamentity.ScopeTypeTenant))

	platformScope := env.platformScope(t)
	_, err = env.scopeService.CreateScope(tenantCtx, &svc.CreateScopeRequest{
		Key:      "tenant-forbidden",
		Name:     "forbidden",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err == nil {
		t.Fatalf("expected non-platform active scope to be rejected")
	}
	if !errors.Is(err, errors.Forbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
}

func TestScopeService_DeleteScope_RemovesLeafAndRebuildsVisibility(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)
	created, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "delete-me",
		Name:     "Delete Me",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope: %v", err)
	}

	if err := env.scopeService.DeleteScope(env.backgroundCtx, created.ID); err != nil {
		t.Fatalf("DeleteScope: %v", err)
	}
	if _, err := env.scopeRepo.Get(env.backgroundCtx, created.ID); err == nil {
		t.Fatalf("expected deleted scope to be unavailable")
	} else if !errors.Is(err, errors.NotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}

	visibleScopeIDs, err := env.scopeRepo.VisibleScopeIDs(env.backgroundCtx, platformScope.ID)
	if err != nil {
		t.Fatalf("VisibleScopeIDs: %v", err)
	}
	if containsScopeID(visibleScopeIDs, created.ID) {
		t.Fatalf("expected deleted scope to be removed from visibility map, got %v", visibleScopeIDs)
	}
}

func TestScopeService_DeleteScope_RejectsProtectedAndReferencedScopes(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)
	_, tenantRoot := env.createTenant(t, "tenant-ref", "Tenant Ref")

	withReason := func(scope *iamentity.Scope, want string) {
		t.Helper()
		err := env.scopeService.DeleteScope(env.backgroundCtx, scope.ID)
		if err == nil {
			t.Fatalf("expected delete to be rejected for scope %s", scope.Key)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error containing %q, got %v", want, err)
		}
		state, stateErr := env.scopeService.ScopeGovernanceState(env.backgroundCtx, scope.ID)
		if stateErr != nil {
			t.Fatalf("ScopeGovernanceState: %v", stateErr)
		}
		if state.CanDelete {
			t.Fatalf("expected scope %s to be non-deletable", scope.Key)
		}
		if !strings.Contains(state.DeleteBlockReason, want) {
			t.Fatalf("expected governance reason containing %q, got %q", want, state.DeleteBlockReason)
		}
	}

	withReason(platformScope, "root scope")
	withReason(tenantRoot, "保留类型")

	childParent, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "parent-scope",
		Name:     "Parent Scope",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope parent: %v", err)
	}
	_, err = env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "child-scope",
		Name:     "Child Scope",
		Type:     "zone",
		ParentID: childParent.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope child: %v", err)
	}
	withReason(childParent, "子授权域")

	roleScope, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "role-bound",
		Name:     "Role Bound",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope role-bound: %v", err)
	}
	if err := env.db.Create(&iamentity.Role{
		TenantID:         "acme",
		OwnerID:          "tenant:acme",
		NamespaceScopeID: roleScope.ID,
		Name:             "role-bound",
		Code:             "role-bound",
		Status:           "active",
	}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	withReason(roleScope, "namespace scope")

	bindingScope, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "binding-bound",
		Name:     "Binding Bound",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope binding-bound: %v", err)
	}
	if err := env.db.Create(&iamentity.UserRoleBinding{
		UserID:       101,
		RoleID:       201,
		GrantScopeID: bindingScope.ID,
		Status:       "active",
	}).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	withReason(bindingScope, "grant scope")

	homeScope, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "home-bound",
		Name:     "Home Bound",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope home-bound: %v", err)
	}
	if err := env.db.Create(&iamentity.User{
		TenantID:       "acme",
		HomeTenantID:   "acme",
		HomeScopeID:    homeScope.ID,
		ManagedScopeID: platformScope.ID,
		OwnerID:        "tenant:acme",
		Username:       "home-user",
		Email:          "home-user@example.com",
		Password:       "hashed-password",
		Status:         "active",
	}).Error; err != nil {
		t.Fatalf("seed home user: %v", err)
	}
	withReason(homeScope, "home scope")

	managedUserScope, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "managed-user-bound",
		Name:     "Managed User Bound",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope managed-user-bound: %v", err)
	}
	if err := env.db.Create(&iamentity.User{
		TenantID:       "acme",
		HomeTenantID:   "acme",
		HomeScopeID:    platformScope.ID,
		ManagedScopeID: managedUserScope.ID,
		OwnerID:        "tenant:acme",
		Username:       "managed-user",
		Email:          "managed-user@example.com",
		Password:       "hashed-password",
		Status:         "active",
	}).Error; err != nil {
		t.Fatalf("seed managed user: %v", err)
	}
	withReason(managedUserScope, "managed scope")

	groupScope, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "group-bound",
		Name:     "Group Bound",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope group-bound: %v", err)
	}
	if err := env.db.Create(&iamentity.Group{
		TenantID:       "acme",
		ManagedScopeID: groupScope.ID,
		OwnerID:        "tenant:acme",
		Name:           "ops",
		ParentKey:      0,
		Level:          1,
		Path:           "/1",
	}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	withReason(groupScope, "managed scope")
}

func TestScopeService_RepairScope_RepairsDriftedChildStructure(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)
	parent, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "cn",
		Name:     "China",
		Type:     "region",
		ParentID: platformScope.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope parent: %v", err)
	}
	child, err := env.scopeService.CreateScope(env.backgroundCtx, &svc.CreateScopeRequest{
		Key:      "shanghai",
		Name:     "Shanghai",
		Type:     "city",
		ParentID: parent.ID,
	})
	if err != nil {
		t.Fatalf("CreateScope child: %v", err)
	}

	parent.Status = iamentity.ScopeStatusInactive
	parent.SetUpdatedAt(time.Now())
	parentGuard, err := svc.NewPlatformEntityConstraint(env.backgroundCtx, svc.ScopeResourceKind, parent)
	if err != nil {
		t.Fatalf("NewPlatformEntityConstraint parent: %v", err)
	}
	if err := env.scopeRepo.UpdateWithConstraint(env.backgroundCtx, parent, parentGuard); err != nil {
		t.Fatalf("UpdateWithConstraint parent: %v", err)
	}

	child.Path = "/broken/path/"
	child.Depth = 99
	child.Status = iamentity.ScopeStatusActive
	child.SetUpdatedAt(time.Now())
	childGuard, err := svc.NewPlatformEntityConstraint(env.backgroundCtx, svc.ScopeResourceKind, child)
	if err != nil {
		t.Fatalf("NewPlatformEntityConstraint child: %v", err)
	}
	if err := env.scopeRepo.UpdateWithConstraint(env.backgroundCtx, child, childGuard); err != nil {
		t.Fatalf("UpdateWithConstraint child: %v", err)
	}

	state, err := env.scopeService.ScopeGovernanceState(env.backgroundCtx, child.ID)
	if err != nil {
		t.Fatalf("ScopeGovernanceState before repair: %v", err)
	}
	if state.HealthStatus != scopeHealthStatusDrifted || !state.CanRepair {
		t.Fatalf("expected drifted repairable scope, got %+v", state)
	}

	repaired, err := env.scopeService.RepairScope(env.backgroundCtx, child.ID)
	if err != nil {
		t.Fatalf("RepairScope: %v", err)
	}
	if repaired.Path != "/platform/cn/shanghai/" {
		t.Fatalf("expected repaired path /platform/cn/shanghai/, got %q", repaired.Path)
	}
	if repaired.Depth != parent.Depth+1 {
		t.Fatalf("expected repaired depth %d, got %d", parent.Depth+1, repaired.Depth)
	}
	if repaired.Status != iamentity.ScopeStatusInactive {
		t.Fatalf("expected repaired status inactive, got %q", repaired.Status)
	}

	state, err = env.scopeService.ScopeGovernanceState(env.backgroundCtx, child.ID)
	if err != nil {
		t.Fatalf("ScopeGovernanceState after repair: %v", err)
	}
	if state.HealthStatus != scopeHealthStatusHealthy || state.CanRepair {
		t.Fatalf("expected healthy scope after repair, got %+v", state)
	}
}

func TestScopeService_RepairScope_RejectsProtectedRoots(t *testing.T) {
	env := setupScopeServiceTest(t)
	defer env.teardown(t)

	platformScope := env.platformScope(t)
	_, tenantRoot := env.createTenant(t, "tenant-protected", "Tenant Protected")

	if _, err := env.scopeService.RepairScope(env.backgroundCtx, platformScope.ID); err == nil {
		t.Fatalf("expected platform root repair to be rejected")
	} else if !strings.Contains(err.Error(), "root scope 暂不支持") {
		t.Fatalf("expected platform root protection error, got %v", err)
	}

	if _, err := env.scopeService.RepairScope(env.backgroundCtx, tenantRoot.ID); err == nil {
		t.Fatalf("expected tenant root repair to be rejected")
	} else if !strings.Contains(err.Error(), "tenant root scope") {
		t.Fatalf("expected tenant root protection error, got %v", err)
	}
}

func containsScopeID(ids []int64, target int64) bool {
	for _, current := range ids {
		if current == target {
			return true
		}
	}
	return false
}
