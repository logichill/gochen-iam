package menu

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	iammw "gochen-iam/middleware"
	menurepo "gochen-iam/repo/menu"
	svc "gochen-iam/service"
	auth "gochen/auth/core"
	"gochen/errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type menuServiceTestEnv struct {
	db            *gorm.DB
	menuRepo      *menurepo.MenuItemRepo
	menuService   *MenuService
	backgroundCtx context.Context
	cancelFunc    context.CancelFunc
}

func setupMenuServiceTest(t *testing.T) *menuServiceTestEnv {
	iammw.RegisterRequiredPermissionDefinitions(svc.AllPermissionDefinitions...)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "menu_test.db")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&iamentity.MenuItem{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	menuRepo, err := menurepo.NewMenuItemRepository(newMenuTestOrm(db))
	if err != nil {
		t.Fatalf("NewMenuItemRepository: %v", err)
	}
	authzRegistry, err := svc.NewIAMAuthzRegistry()
	if err != nil {
		t.Fatalf("NewIAMAuthzRegistry: %v", err)
	}
	authorizer, err := svc.NewIAMAuthorizer(nil, authzRegistry)
	if err != nil {
		t.Fatalf("NewIAMAuthorizer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, err = auth.WithPrincipal(ctx, auth.Principal{
		SubjectID:     1,
		Permissions:   []string{"*:*:*"},
		IsSystem:      true,
		ActiveScopeID: 1,
	})
	if err != nil {
		t.Fatalf("WithPrincipal: %v", err)
	}
	ctx = iamauth.BindActiveScopeContext(ctx, 1, string(iammw.ScopePlatform))
	return &menuServiceTestEnv{
		db:            db,
		menuRepo:      menuRepo,
		menuService:   NewMenuService(menuRepo, authorizer),
		backgroundCtx: ctx,
		cancelFunc:    cancel,
	}
}

func (env *menuServiceTestEnv) teardown(t *testing.T) {
	env.cancelFunc()
	sqlDB, err := env.db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}

func (env *menuServiceTestEnv) createMenuItem(t *testing.T, req *CreateMenuItemRequest) *iamentity.MenuItem {
	t.Helper()
	item, err := env.menuService.CreateMenuItem(env.backgroundCtx, req)
	if err != nil {
		t.Fatalf("create menu item: %v", err)
	}
	return item
}

func TestMenuServiceCreateMenuItem_FailsClosedWithoutAuthorizer(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	menuService := NewMenuService(env.menuRepo, nil)
	_, err := menuService.CreateMenuItem(context.Background(), &CreateMenuItemRequest{
		Code:      "root",
		Title:     "Root",
		Type:      iamentity.MenuTypeGroup,
		Published: true,
	})
	if !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("expected invalid input error, got %v", err)
	}
}

func TestMenuServiceUpdateMenuItem_KeepParentWhenParentIDOmitted(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	root := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "root",
		Title:     "Root",
		Type:      iamentity.MenuTypeGroup,
		Published: true,
	})
	rootID := root.GetID()
	child := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "child",
		ParentID:  &rootID,
		Title:     "Child",
		Path:      "/child",
		Type:      iamentity.MenuTypePage,
		Published: true,
	})

	title := "Child V2"
	emptyPath := ""
	updated, err := env.menuService.UpdateMenuItem(env.backgroundCtx, child.GetID(), &UpdateMenuItemRequest{
		Title: title,
		Path:  &emptyPath,
	})
	if err != nil {
		t.Fatalf("update menu item: %v", err)
	}
	if updated.ParentID == nil || *updated.ParentID != rootID {
		t.Fatalf("expected parent to stay %d, got %v", rootID, updated.ParentID)
	}
	if updated.Title != "Child V2" {
		t.Fatalf("expected title updated, got %q", updated.Title)
	}
	if updated.Path != "" {
		t.Fatalf("expected path cleared, got %q", updated.Path)
	}
}

func TestMenuServiceUpdateMenuItem_UnsetParentWithExplicitNil(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	root := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "root",
		Title:     "Root",
		Type:      iamentity.MenuTypeGroup,
		Published: true,
	})
	rootID := root.GetID()
	child := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "child",
		ParentID:  &rootID,
		Title:     "Child",
		Type:      iamentity.MenuTypePage,
		Published: true,
	})

	updated, err := env.menuService.UpdateMenuItem(
		env.backgroundCtx,
		child.GetID(),
		&UpdateMenuItemRequest{},
		svc.ValueFieldPatch(func(item *iamentity.MenuItem, parentID *int64) {
			item.ParentID = parentID
		}, (*int64)(nil)),
	)
	if err != nil {
		t.Fatalf("unset menu parent: %v", err)
	}
	if updated.ParentID != nil {
		t.Fatalf("expected parent to be cleared, got %v", updated.ParentID)
	}
}

func TestMenuServiceUpdateMenuItem_ReparentWithExplicitValue(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	rootA := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "root-a",
		Title:     "Root A",
		Type:      iamentity.MenuTypeGroup,
		Published: true,
	})
	rootB := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "root-b",
		Title:     "Root B",
		Type:      iamentity.MenuTypeGroup,
		Published: true,
	})
	rootAID := rootA.GetID()
	rootBID := rootB.GetID()
	child := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "child",
		ParentID:  &rootAID,
		Title:     "Child",
		Type:      iamentity.MenuTypePage,
		Published: true,
	})

	published := false
	updated, err := env.menuService.UpdateMenuItem(
		env.backgroundCtx,
		child.GetID(),
		&UpdateMenuItemRequest{Published: &published},
		svc.ValueFieldPatch(func(item *iamentity.MenuItem, parentID *int64) {
			item.ParentID = parentID
		}, &rootBID),
	)
	if err != nil {
		t.Fatalf("reparent menu item: %v", err)
	}
	if updated.ParentID == nil || *updated.ParentID != rootBID {
		t.Fatalf("expected parent to change to %d, got %v", rootBID, updated.ParentID)
	}
	if updated.Published {
		t.Fatalf("expected published to be updated to false")
	}
}
