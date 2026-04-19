package router

import (
	"testing"

	iamentity "gochen-iam/entity"
	svc "gochen-iam/service"
	scopesvc "gochen-iam/service/scope"
)

func TestScopeRoutes_RegisterRoutes(t *testing.T) {
	routes := map[string]struct{}{}
	root := newRecordingGroup("", routes)

	sr := NewScopeRoutes(nil, &scopesvc.ScopeService{})
	if err := sr.RegisterRoutes(root); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}

	want := []string{
		"GET /scopes",
		"GET /scopes/:id/visibility",
		"POST /scopes",
		"PUT /scopes/:id",
		"POST /scopes/:id/activate",
		"POST /scopes/:id/deactivate",
		"POST /scopes/:id/repair",
		"DELETE /scopes/:id",
	}
	for _, route := range want {
		if _, ok := routes[route]; !ok {
			t.Fatalf("missing route: %s", route)
		}
	}
}

func TestToScopeListItem_ProjectsGovernanceHealthState(t *testing.T) {
	parentID := int64(100)
	scope := &iamentity.Scope{
		Key:      "shanghai",
		Name:     "Shanghai",
		Type:     "city",
		ParentID: &parentID,
		Path:     "/platform/cn/shanghai/",
		Depth:    3,
		Status:   iamentity.ScopeStatusInactive,
	}
	scope.SetID(101)
	governance := &svc.ScopeGovernanceState{
		ChildCount:        0,
		CanDelete:         true,
		HealthStatus:      "drifted",
		HealthReason:      "当前授权域的 path/depth 与父授权域不一致，可执行修复。",
		CanRepair:         true,
		DeleteBlockReason: "",
	}

	item := toScopeListItem(scope, governance)

	if item.ID != 101 || item.ParentID == nil || *item.ParentID != parentID {
		t.Fatalf("unexpected scope identity projection: %+v", item)
	}
	if item.HealthStatus != "drifted" {
		t.Fatalf("expected health status drifted, got %q", item.HealthStatus)
	}
	if item.HealthReason != governance.HealthReason {
		t.Fatalf("expected health reason %q, got %q", governance.HealthReason, item.HealthReason)
	}
	if !item.CanRepair {
		t.Fatalf("expected can_repair=true, got %+v", item)
	}
	if !item.CanDelete {
		t.Fatalf("expected can_delete=true, got %+v", item)
	}
}
