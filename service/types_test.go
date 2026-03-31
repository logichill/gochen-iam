package service

import (
	"encoding/json"
	"testing"
)

func TestUpdateGroupRequestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		parentIDSet bool
		parentID    *int64
	}{
		{
			name:        "omit parent_id",
			payload:     `{"name":"group-a"}`,
			parentIDSet: false,
			parentID:    nil,
		},
		{
			name:        "explicit null parent_id",
			payload:     `{"name":"group-a","parent_id":null}`,
			parentIDSet: true,
			parentID:    nil,
		},
		{
			name:        "explicit value parent_id",
			payload:     `{"name":"group-a","parent_id":42}`,
			parentIDSet: true,
			parentID:    int64Ptr(42),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req UpdateGroupRequest
			if err := json.Unmarshal([]byte(tt.payload), &req); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if req.ParentIDSet != tt.parentIDSet {
				t.Fatalf("expected ParentIDSet=%v, got %v", tt.parentIDSet, req.ParentIDSet)
			}
			if !sameInt64Ptr(req.ParentID, tt.parentID) {
				t.Fatalf("expected ParentID=%v, got %v", tt.parentID, req.ParentID)
			}
		})
	}
}

func TestAllPermissionDefinitions_IncludeActionAndMenuVisibilityPatterns(t *testing.T) {
	assertContainsDefinition := func(code string) {
		t.Helper()
		for _, def := range AllPermissionDefinitions {
			if def.Code == code {
				return
			}
		}
		t.Fatalf("expected permission definition %q to be registered", code)
	}

	assertContainsDefinition("action:mcp:invoke")
	assertContainsDefinition("menu:*:view")
}

func int64Ptr(v int64) *int64 {
	return &v
}

func sameInt64Ptr(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
