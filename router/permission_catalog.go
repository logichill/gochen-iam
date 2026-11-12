package router

import (
	iammw "gochen-iam/middleware"
	runtimehttp "gochen-runtime/http"
	"gochen/auth"
	"gochen/errors"
	"gochen/httpx"
)

// PermissionCatalogOptions controls the permission catalog response.
type PermissionCatalogOptions struct {
	Service         string
	ExposeCallsites bool
}

// RegisterPermissionCatalogRoute registers GET /permissions on the given route group.
func RegisterPermissionCatalogRoute(group httpx.IRouteGroup, options PermissionCatalogOptions) error {
	if group == nil {
		return errors.NewCode(errors.InvalidInput, "route group cannot be nil")
	}

	service := options.Service
	if service == "" {
		service = "iam"
	}
	registry, _, err := runtimehttp.EntryRegistryFrom(group)
	if err != nil {
		return err
	}
	if registry != nil {
		if err := runtimehttp.BindEntry(group, "GET", "/permissions", auth.EntryBinding{
			ResourceAccess: auth.ResourceAccessNone,
			Source:         "iam.router.RegisterPermissionCatalogRoute -> in-memory permission registration metadata and redacted callsites",
			AllowReason:    "permission definitions are registration metadata; the caller's route group retains its authentication and management middleware",
		}); err != nil {
			return err
		}
	}

	return runtimehttp.RegisterRoute(group, "GET", "/permissions", func(ctx httpx.IContext) error {
		resp := map[string]any{
			"service":                         service,
			"required_permissions":            iammw.RequiredPermissions(),
			"required_permission_definitions": iammw.RequiredPermissionDefinitions(),
		}
		if options.ExposeCallsites {
			resp["required_permissions_callsites"] = iammw.RequiredPermissionsWithRedactedCallsites()
		}
		return httpx.WriteSuccess(ctx, resp)
	})
}
