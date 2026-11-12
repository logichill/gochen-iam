package router

import (
	"testing"

	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestRoleMembersActualHTTPEntriesUseManagedResources(t *testing.T) {
	routes, _ := roleRoutesFixture(t)
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/iam"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.RegisterRoutes(group); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, entry := range entries.Report() {
		if entry.Action != "users" {
			continue
		}
		seen = true
		if entry.Class != auth.EntryDeclared || entry.ConditionPath == "" {
			t.Fatalf("member entry=%+v", entry)
		}
		names := []string{"users", "groups", "member_roles"}
		if len(entry.Resources) != len(names) {
			t.Fatalf("incomplete member resources=%+v", entry)
		}
		for i, name := range names {
			if entry.Resources[i].Name != name || entry.Resources[i].ConditionPath == "" {
				t.Fatalf("member resource=%+v", entry.Resources[i])
			}
		}
	}
	if !seen {
		t.Fatalf("missing actual member entry: %v", seen)
	}
}
