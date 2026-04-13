package menu

import (
	"testing"
	"time"

	iamentity "gochen-iam/entity"
	"gochen/errorx"
)

func TestMenuServiceCreateEntity_RejectsManagedFields(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	item := &iamentity.MenuItem{
		Code:  "dashboard",
		Title: "Dashboard",
		Type:  iamentity.MenuTypePage,
	}
	item.ID = 99
	item.Version = 3
	item.CreatedAt = time.Now()

	err := env.menuService.CreateEntity(env.backgroundCtx, item)
	if !errorx.Is(err, errorx.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestMenuServiceUpdateEntity_RejectsImmutableFieldMutation(t *testing.T) {
	env := setupMenuServiceTest(t)
	defer env.teardown(t)

	item := env.createMenuItem(t, &CreateMenuItemRequest{
		Code:      "dashboard",
		Title:     "Dashboard",
		Type:      iamentity.MenuTypePage,
		Published: true,
	})

	candidate := *item
	candidate.Code = "dashboard-v2"

	err := env.menuService.UpdateEntity(env.backgroundCtx, &candidate)
	if !errorx.Is(err, errorx.Validation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}
