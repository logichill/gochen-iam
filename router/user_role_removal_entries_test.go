package router

import (
	"strings"
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestUserRoleRemovalBindsActualHTTPEntries(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerRoleRemovalRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, entry := range registry.Report() {
		switch entry.Class {
		case auth.EntryDeclared:
			declared++
			count := 2
			if strings.Contains(entry.Entry.Key, "role-bindings") {
				count = 4
			}
			if entry.Module != "iam" || entry.ResourceAccess != auth.ResourceAccessData || len(entry.Resources) != count || entry.Resources[0].Name != "role" || entry.Resources[1].Name != "binding" {
				t.Fatalf("incomplete removal=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid removal=%+v", entry)
		}
	}
	if len(server.Routes()) != 4 || declared != 2 || allowed != 2 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound role removal passed the gate")
	}
	t.Log("role removal actual=4 declared=2 explicit_allow=2 invalid=0")
}
