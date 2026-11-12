package router

import (
	"strings"
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestUserSelfBindsEveryActualHTTPEntry(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam/users"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.setupSelfUserRoutes(group); err != nil {
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
			if status.Module != "iam" || status.ResourceAccess != auth.ResourceAccessData || status.ConditionPath == "" {
				t.Fatalf("invalid self plan=%+v", status)
			}
			count := 2
			if status.Action == "update_profile_user" {
				count = 1
			} else if status.Action == "change_password_user" {
				count = 0
			}
			if len(status.Resources) != count {
				t.Fatalf("incomplete self resources=%+v", status)
			}
		case auth.EntryAllowed:
			allowed++
		default:
			t.Fatalf("invalid actual self entry=%+v", status)
		}
	}
	if declared != 4 || allowed != 2 || len(server.Routes()) != 6 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d", len(server.Routes()), declared, allowed)
	}
	missing := hostauthz.NewEntryRegistry()
	if err := missing.ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("unbound self entries passed the gate")
	}
	t.Log("user self actual=6 declared=4 explicit_allow=2 invalid=0")
}

func TestUserRootValidatesPermissionsAndEveryCustomEntry(t *testing.T) {
	routes, _ := userAssociationRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	registry := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam"), registry, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	declared, allowed, invalid := 0, 0, 0
	for _, status := range registry.Report() {
		switch status.Class {
		case auth.EntryDeclared:
			declared++
		case auth.EntryAllowed:
			allowed++
		default:
			invalid++
			if !strings.Contains(status.Entry.Key, "/permissions") && !strings.Contains(status.Entry.Key, "/check-permission") {
				t.Fatalf("unexpected remaining User entry=%+v", status)
			}
		}
	}
	if declared != 33 || allowed != 17 || invalid != 0 || len(server.Routes()) != 50 {
		t.Fatalf("actual=%d declared=%d explicit_allow=%d invalid=%d", len(server.Routes()), declared, allowed, invalid)
	}
	t.Log("user actual=50 declared=33 explicit_allow=17 invalid=0; full root verified")
}
