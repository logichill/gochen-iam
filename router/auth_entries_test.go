package router

import (
	"net/http/httptest"
	"testing"

	iammw "gochen-iam/middleware"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
)

func TestAuthCredentialProtocolsRegisterExactEntries(t *testing.T) {
	routes := NewAuthRoutesWithConfig(&authRoutesUserServiceStub{}, &iammw.AuthConfig{SecretKey: "protocol-test-secret"})
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
	if len(server.Routes()) != 17 {
		t.Fatalf("auth actual entries=%d, want 8 credential endpoints, HEAD csrf and 8 OPTIONS", len(server.Routes()))
	}
	for _, entry := range registry.Report() {
		if entry.Class != auth.EntryAllowed || entry.ResourceAccess != auth.ResourceAccessNone || entry.AllowReason == "" || entry.Source == "" {
			t.Fatalf("invalid credential protocol binding=%+v", entry)
		}
	}
	if err := hostauthz.NewEntryRegistry().ValidateEntries(t.Context(), server); err == nil {
		t.Fatal("credential endpoints disappeared from actual entry validation")
	}
	// Registration does not replace the refresh credential validation.
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest("POST", "/iam/auth/refresh", nil))
	if recorder.Code < 400 {
		t.Fatalf("missing refresh credential allowed: %d %s", recorder.Code, recorder.Body.String())
	}
}
