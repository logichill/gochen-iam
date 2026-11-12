package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iammw "gochen-iam/middleware"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth"
	"gochen/errors"
	"gochen/httpx"
)

func TestRegisterPermissionCatalogRoute(t *testing.T) {
	routes := map[string]struct{}{}
	group := newRecordingGroup("/docs", routes)

	if err := RegisterPermissionCatalogRoute(group, PermissionCatalogOptions{Service: "test"}); err != nil {
		t.Fatalf("RegisterPermissionCatalogRoute failed: %v", err)
	}

	if _, ok := routes["GET /docs/permissions"]; !ok {
		t.Fatalf("expected GET /docs/permissions to be registered, got %#v", routes)
	}
}

func TestPermissionCatalogBindsItsActualRegistrationMetadata(t *testing.T) {
	for _, expose := range []bool{false, true} {
		server := nethttp.NewServer(&runtimehttp.WebConfig{})
		entries := hostauthz.NewEntryRegistry()
		group, err := runtimehttp.WithEntryRegistry(server.Group("/custom/docs"), entries, "iam")
		if err != nil {
			t.Fatal(err)
		}
		if err := RegisterPermissionCatalogRoute(group, PermissionCatalogOptions{Service: "test", ExposeCallsites: expose}); err != nil {
			t.Fatal(err)
		}
		if err := entries.ValidateEntries(t.Context(), server); err != nil {
			t.Fatal(err)
		}
		report := entries.Report()
		if len(server.Routes()) != 3 || len(report) != 3 {
			t.Fatalf("actual=%d bindings=%d", len(server.Routes()), len(report))
		}
		for _, entry := range report {
			if entry.Class != auth.EntryAllowed || entry.ResourceAccess != auth.ResourceAccessNone || entry.AllowReason == "" || entry.Source == "" {
				t.Fatalf("invalid metadata entry=%+v", entry)
			}
			if !strings.HasPrefix(entry.Entry.Key, "OPTIONS ") && entry.Module != "iam" {
				t.Fatalf("metadata entry lost module=%+v", entry)
			}
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/custom/docs/permissions", nil))
		body := recorder.Body.String()
		if recorder.Code != http.StatusOK || !strings.Contains(body, `"service":"test"`) || !strings.Contains(body, `"required_permission_definitions"`) {
			t.Fatalf("response=%d %s", recorder.Code, body)
		}
		if strings.Contains(body, `"required_permissions_callsites"`) != expose {
			t.Fatalf("callsites response=%s", body)
		}
	}
}

func TestPermissionCatalogPreservesHostManagementMiddleware(t *testing.T) {
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	entries := hostauthz.NewEntryRegistry()
	group, err := runtimehttp.WithEntryRegistry(server.Group("/docs"), entries, "iam")
	if err != nil {
		t.Fatal(err)
	}
	group.Use(iammw.UserOnlyMiddleware())
	if err := RegisterPermissionCatalogRoute(group, PermissionCatalogOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := entries.ValidateEntries(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/docs/permissions", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("host guard lost: %d %s", recorder.Code, recorder.Body.String())
	}
}

type rejectingCatalogEntries struct{}

func (rejectingCatalogEntries) BindHTTP(string, string, auth.EntryBinding) error {
	return errors.NewCode(errors.InvalidInput, "injected binding rejection")
}

func TestPermissionCatalogBindingFailurePreventsRouteRegistration(t *testing.T) {
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	group, err := runtimehttp.WithEntryRegistry(server.Group("/docs"), rejectingCatalogEntries{}, "iam")
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterPermissionCatalogRoute(group, PermissionCatalogOptions{}); !errors.Is(err, errors.InvalidInput) || len(server.Routes()) != 0 {
		t.Fatalf("error=%v actual=%d", err, len(server.Routes()))
	}
	if err := RegisterPermissionCatalogRoute(httpx.IRouteGroup(nil), PermissionCatalogOptions{}); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("nil group err=%v", err)
	}
}
