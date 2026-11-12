package router

import (
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestUserGroupWritesBindEveryActualHTTPEntry(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.registerGroupWriteRoutes(group); err != nil {
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
			if status.Module != "iam" || status.ResourceAccess != auth.ResourceAccessData || status.ConditionPath == "" || len(status.Resources) != 1 || status.Resources[0].Name != "group" || status.Resources[0].ConditionPath == "" {
				t.Fatalf("incomplete association write plan=%+v", status)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid association write entry=%+v", status)
		}
	}
	if declared != 2 || allowed != 2 || len(server.Routes()) != 4 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	missing := hostauthz.NewEntryRegistry()
	if err := missing.ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound association writes passed the entry gate")
	}
	t.Log("user group writes actual=4 declared=2 explicit_allow=2 invalid=0")
}

func TestUserMigratedSubsetCountsUniqueActualEntries(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	for _, register := range []func() error{
		func() error { return routes.registerAssociationReadRoutes(group) },
		func() error { return routes.registerStatusRoutes(group) },
		func() error { return routes.registerGroupWriteRoutes(group) },
		func() error { return routes.registerRoleAssignmentRoutes(group) },
		func() error { return routes.registerRoleRemovalRoutes(group) },
		func() error { return routes.registerRoleBindingReadRoutes(group) },
	} {
		if err := register(); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed := 0, 0
	for _, status := range registry.Report() {
		switch status.Class {
		case auth.EntryDeclared:
			declared++
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid migrated entry=%+v", status)
		}
	}
	if declared != 16 || allowed != 10 || len(server.Routes()) != 26 {
		t.Fatalf("actual unique=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	t.Log("migrated User subset actual unique=26 declared=16 explicit_allow=10 invalid=0; shared groups/roles/bindings OPTIONS counted once")
}
