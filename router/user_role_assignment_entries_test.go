package router

import (
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestUserRoleAssignmentBindsEveryActualHTTPEntry(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerRoleAssignmentRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, status := range registry.Report() {
		switch status.Class {
		case auth.EntryDeclared:
			declared++
			if status.Module != "iam" || status.ResourceAccess != auth.ResourceAccessData || len(status.Resources) != 2 || status.Resources[0].Name != "role" || status.Resources[1].Name != "binding" {
				t.Fatalf("incomplete assignment=%+v", status)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid assignment=%+v", status)
		}
	}
	if len(server.Routes()) != 4 || declared != 2 || allowed != 2 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	missing := hostauthz.NewEntryRegistry()
	if err := missing.ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound role assignments passed the gate")
	}
	t.Log("role assignment actual=4 declared=2 explicit_allow=2 invalid=0")
}
