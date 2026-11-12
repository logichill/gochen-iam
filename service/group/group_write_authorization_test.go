package group_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	scoperepo "gochen-iam/repo/scope"
	tenantrepo "gochen-iam/repo/tenant"
	svc "gochen-iam/service"
	groupsvc "gochen-iam/service/group"
	hostauthz "gochen-runtime/host/authz"
	"gochen/contextx"
	"gochen/errors"
	"gochen/testkit"
	"gorm.io/gorm"
)

func TestGroupUpdateReadsCurrentEntityOnce(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	item := createAssociationGroup(t, env)
	var reads atomic.Int64
	if err := env.db.Callback().Query().After("gorm:query").Register("group-write:current-reads", func(tx *gorm.DB) {
		if tx.Statement.Table == "groups" && !strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "count(") {
			reads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	result, err := env.groupService.UpdateGroup(env.backgroundCtx, item.ID, &svc.UpdateGroupRequest{Description: "service"})
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || result.Version != 1 {
		t.Fatalf("reads=%d result=%+v", reads.Load(), result)
	}
	reads.Store(0)
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write", "group:api:manage")
	result.Description = "http"
	if err := env.groupService.HTTPApplication().Update(ctx, result); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || result.Version != 2 {
		t.Fatalf("HTTP reads=%d result=%+v", reads.Load(), result)
	}
}

func TestGroupWriteRejectsBeforeResourceReads(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	reads, writes := countAssociationAccess(t, env.db)
	untrusted, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{untrusted, associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")} {
		if _, err := env.groupService.CreateGroup(ctx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "denied"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("create denial=%v", err)
		}
		if _, err := env.groupService.UpdateGroup(ctx, 1, &svc.UpdateGroupRequest{Name: "denied"}); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("update denial=%v", err)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("group write denial reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func createGroupBranch(t *testing.T, env *groupServiceTestEnv) (root, parent, child *iamentity.Group) {
	t.Helper()
	root = createAssociationGroup(t, env)
	var err error
	parent, err = env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "other-root"})
	if err != nil {
		t.Fatal(err)
	}
	id := root.GetID()
	child, err = env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "child", ParentID: &id})
	if err != nil {
		t.Fatal(err)
	}
	return root, parent, child
}

func moveGroup(t *testing.T, env *groupServiceTestEnv, ctx context.Context, groupID, parentID int64) (*iamentity.Group, error) {
	t.Helper()
	return env.groupService.UpdateGroup(ctx, groupID, &svc.UpdateGroupRequest{}, svc.ValueFieldPatch(func(group *iamentity.Group, id *int64) { group.ParentID = id }, &parentID))
}

func TestGroupWritePrechecksInvisibleSubtreeBeforeFirstWrite(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root, parent, child := createGroupBranch(t, env)
	if err := env.db.Model(child).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	_, writes := countAssociationAccess(t, env.db)
	if err := env.db.Callback().Query().Before("gorm:query").Register("group-write:no-preloads", func(tx *gorm.DB) {
		if len(tx.Statement.Preloads) > 0 || tx.Statement.Table != "groups" {
			tx.AddError(errors.NewCode(errors.Internal, "group write read an implicit association"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	if _, err := moveGroup(t, env, ctx, root.GetID(), parent.GetID()); !errors.Is(err, errors.NotFound) || writes.Load() != 0 {
		t.Fatalf("invisible subtree update=%v writes=%d", err, writes.Load())
	}
}

func TestGroupWritePreservesTenantWideNameUniqueness(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root, parent, _ := createGroupBranch(t, env)
	if err := env.db.Model(parent).Update("managed_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	_, writes := countAssociationAccess(t, env.db)
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	if _, err := env.groupService.UpdateGroup(ctx, root.GetID(), &svc.UpdateGroupRequest{Name: parent.Name}); !errors.Is(err, errors.Validation) || writes.Load() != 0 {
		t.Fatalf("hidden name duplicate=%v writes=%d", err, writes.Load())
	}
	if _, err := env.groupService.CreateGroup(ctx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: parent.Name}); !errors.Is(err, errors.Validation) || writes.Load() != 0 {
		t.Fatalf("hidden create duplicate=%v writes=%d", err, writes.Load())
	}
}

func TestGroupWriteRollsBackRootAndDescendantsOnFailure(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root, parent, child := createGroupBranch(t, env)
	var updates atomic.Int64
	if err := env.db.Callback().Update().Before("gorm:update").Register("group-write:fail-child", func(tx *gorm.DB) {
		if tx.Statement.Table == "groups" && updates.Add(1) == 2 {
			tx.AddError(errors.NewCode(errors.Database, "forced subtree write failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := moveGroup(t, env, env.backgroundCtx, root.GetID(), parent.GetID()); !errors.Is(err, errors.Database) || updates.Load() != 2 {
		t.Fatalf("subtree failure=%v updates=%d", err, updates.Load())
	}
	for _, original := range []*iamentity.Group{root, child} {
		var stored iamentity.Group
		if err := env.db.First(&stored, original.GetID()).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Path != original.Path || stored.Level != original.Level || stored.GetVersion() != original.GetVersion() {
			t.Fatalf("failed move changed node=%+v", stored)
		}
	}
}

func TestGroupWriteMovesEverySubtreePage(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	root := createAssociationGroup(t, env)
	parent, err := env.groupService.CreateGroup(env.backgroundCtx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "new-parent"})
	if err != nil {
		t.Fatal(err)
	}
	id := root.GetID()
	children := make([]*iamentity.Group, 1001)
	for i := range children {
		childID := int64(i + 100)
		children[i] = &iamentity.Group{TenantID: env.tenantID, ManagedScopeID: 1, OwnerID: svc.TenantOwnerID(env.tenantID), ParentID: &id, ParentKey: id,
			Name: fmt.Sprintf("child-%d", i), Level: 2, Path: root.Path + "/" + strconv.FormatInt(childID, 10)}
		children[i].SetID(childID)
	}
	if err := env.db.CreateInBatches(children, 100).Error; err != nil {
		t.Fatal(err)
	}
	ctx := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	moved, err := moveGroup(t, env, ctx, id, parent.GetID())
	if err != nil || moved.Parent == nil || moved.Parent.GetID() != parent.GetID() {
		t.Fatalf("move pages=%+v error=%v", moved, err)
	}
	var count int64
	if err := env.db.Model(&iamentity.Group{}).Where("parent_id = ? AND level = 3 AND version = 1 AND path LIKE ?", id, moved.Path+"/%").Count(&count).Error; err != nil || count != 1001 {
		t.Fatalf("moved child pages=%d error=%v", count, err)
	}
}

func TestGroupWriteResolvesMissingManagedScopeThroughDeclaredProviders(t *testing.T) {
	env := setupGroupServiceTest(t)
	defer env.teardown(t)
	if err := env.db.AutoMigrate(&iamentity.Tenant{}); err != nil {
		t.Fatal(err)
	}
	scopes, err := scoperepo.NewScopeRepository(env.groupRepo.Orm(), testkit.NewInt64Sequence(9))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := tenantrepo.NewTenantRepository(env.groupRepo.Orm(), testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatal(err)
	}
	root := &iamentity.Scope{Key: "tenant:" + env.tenantID, Name: "tenant-root", Type: "tenant", Path: "/tenant/"}
	root.SetID(9)
	id := root.GetID()
	if err := env.db.Create(root).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&iamentity.Tenant{Key: env.tenantID, Name: "tenant", RootScopeID: &id}).Error; err != nil {
		t.Fatal(err)
	}
	scopeAuthorizer := svc.NewScopeAuthorizer(scopes, tenants)
	service, err := groupsvc.NewGroupService(env.groupRepo, env.userRepo, env.roleRepo, scopeAuthorizer, svc.NewIAMAccess(scopeAuthorizer), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := hostauthz.WithPrincipal(env.backgroundCtx, hostauthz.Principal{SubjectID: "1", IsSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	group, err := service.CreateGroup(ctx, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "resolved"})
	if err != nil || group.ManagedScopeID != 9 || group.Path != "/"+strconv.FormatInt(group.GetID(), 10) {
		t.Fatalf("resolved group=%+v error=%v", group, err)
	}
	var scopeReads atomic.Int64
	if err := env.db.Callback().Query().Before("gorm:query").Register("group-write:count-scope-providers", func(tx *gorm.DB) {
		if tx.Statement.Table == "tenants" || tx.Statement.Table == "scopes" {
			scopeReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	denied := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:read")
	if _, err := service.CreateGroup(denied, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "denied-root"}); !errors.Is(err, errors.Forbidden) || scopeReads.Load() != 0 {
		t.Fatalf("denied root resolver=%v provider reads=%d", err, scopeReads.Load())
	}
	existingScope := associationPrincipal(t, env.tenantID, "7", "platform", "group:api:write")
	group, err = service.CreateGroup(existingScope, &svc.CreateGroupRequest{TenantID: env.tenantID, Name: "existing-scope"})
	if err != nil || group.ManagedScopeID != 1 || scopeReads.Load() != 0 {
		t.Fatalf("existing scope must skip tenant/root resources group=%+v error=%v provider reads=%d", group, err, scopeReads.Load())
	}
}
