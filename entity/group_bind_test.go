package entity

import (
	"net/http/httptest"
	"strings"
	"testing"

	"gochen-runtime/http/nethttp"
)

func TestGroupBindJSON_AllowsCompatibilityCodeField(t *testing.T) {
	req := httptest.NewRequest("POST", "/groups", strings.NewReader(`{"name":"管理员","code":"admin","parent_id":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ctx, err := nethttp.NewBaseContext(rec, req)
	if err != nil {
		t.Fatalf("NewBaseContext: %v", err)
	}

	var group Group
	if err := ctx.BindJSON(&group); err != nil {
		t.Fatalf("BindJSON: %v", err)
	}
	if group.Code != "admin" {
		t.Fatalf("expected code to be bound, got %q", group.Code)
	}
	if group.ParentID == nil || *group.ParentID != 1 {
		t.Fatalf("expected parent_id=1, got %#v", group.ParentID)
	}
}
