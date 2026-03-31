package router

import (
	"encoding/json"
	"testing"

	iamentity "gochen-iam/entity"
	menusvc "gochen-iam/service/menu"
	restapi "gochen/api/restapi"
)

func TestMenuUpdatePatches_ParentIDPatchSemantics(t *testing.T) {
	t.Run("omit parent_id keeps original parent", func(t *testing.T) {
		patches := menuUpdatePatches(restapi.JSONBodyFields{
			"title": json.RawMessage(`"菜单"`),
		}, &menusvc.UpdateMenuItemRequest{
			Title: "菜单",
		})
		if len(patches) != 0 {
			t.Fatalf("expected no parent patch when parent_id is omitted, got %d", len(patches))
		}
	})

	t.Run("null parent_id clears parent", func(t *testing.T) {
		patches := menuUpdatePatches(restapi.JSONBodyFields{
			"parent_id": json.RawMessage("null"),
		}, &menusvc.UpdateMenuItemRequest{})
		if len(patches) != 1 {
			t.Fatalf("expected one parent patch, got %d", len(patches))
		}
		item := &iamentity.MenuItem{ParentID: int64Ptr(7)}
		if err := patches[0].Apply(item); err != nil {
			t.Fatalf("apply patch: %v", err)
		}
		if item.ParentID != nil {
			t.Fatalf("expected parent to be cleared, got %v", item.ParentID)
		}
	})

	t.Run("value parent_id creates explicit reparent patch", func(t *testing.T) {
		parentID := int64(42)
		patches := menuUpdatePatches(restapi.JSONBodyFields{
			"parent_id": json.RawMessage("42"),
		}, &menusvc.UpdateMenuItemRequest{
			ParentID: &parentID,
		})
		if len(patches) != 1 {
			t.Fatalf("expected one parent patch, got %d", len(patches))
		}
		item := &iamentity.MenuItem{}
		if err := patches[0].Apply(item); err != nil {
			t.Fatalf("apply patch: %v", err)
		}
		if item.ParentID == nil || *item.ParentID != parentID {
			t.Fatalf("expected parent %d, got %v", parentID, item.ParentID)
		}
	})
}

func int64Ptr(v int64) *int64 {
	return &v
}
