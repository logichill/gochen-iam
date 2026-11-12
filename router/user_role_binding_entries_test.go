package router

import (
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestUserRoleBindingReadBindsEveryActualHTTPEntry(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerRoleBindingReadRoutes(group); err != nil {
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
			if entry.Module != "iam" || entry.ResourceAccess != auth.ResourceAccessData || len(entry.Resources) != 2 || entry.Resources[0].Name != "binding" || entry.Resources[1].Name != "role" {
				t.Fatalf("incomplete projection=%+v", entry)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid projection=%+v", entry)
		}
	}
	if len(server.Routes()) != 3 || declared != 2 || allowed != 1 {
		t.Fatalf("actual=%d declared=%d allowed=%d", len(server.Routes()), declared, allowed)
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound projection passed the gate")
	}
	t.Log("role binding read actual=3 declared=2 explicit_allow=1 invalid=0")
}
