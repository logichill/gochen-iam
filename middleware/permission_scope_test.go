package middleware

import (
	"context"
	"testing"

	iamauth "gochen-iam/auth"
	"gochen-iam/tenant"
	authz "gochen-runtime/host/authz"
	"gochen/errors"
)

func TestPermissionMiddlewareEnforcesDeclaredScopes(t *testing.T) {
	resetRequiredPermissionsRegistryForTest()
	t.Cleanup(resetRequiredPermissionsRegistryForTest)
	spec := ApiPermission(ResourceMenu, ActionManage).Scope(ScopePlatform)
	RegisterRequiredPermissionDefinitions(spec.Definition())

	for _, tt := range []struct {
		name       string
		mode       string
		scope      string
		registered bool
		allowed    bool
	}{
		{name: "platform", mode: "tenant", scope: "platform", allowed: true},
		{name: "tenant wildcard", mode: "tenant", scope: "tenant"},
		{name: "missing scope", mode: "tenant"},
		{name: "registered metadata", mode: "tenant", scope: "tenant", registered: true},
		{name: "single tenant", mode: "single", allowed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base, err := authz.WithPrincipal(tenant.WithPolicy(context.Background(), tenant.Policy{Mode: tenant.Mode(tt.mode)}), authz.Principal{
				SubjectID: 7, ActiveScopeID: 101, Permissions: []string{"*:*:*"},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx := newTestHTTPContext(t, "GET", "/menus")
			ctx.SetContext(ctx.RequestContext().WithContext(iamauth.BindActiveScopeContext(base, 101, tt.scope)))
			required := spec
			if tt.registered {
				required = PermissionCode(spec.Code)
			}
			called := false
			err = PermissionMiddleware(required)(ctx, func() error { called = true; return nil })
			if tt.allowed {
				if err != nil || !called {
					t.Fatalf("allowed request: next=%v err=%v", called, err)
				}
			} else if !errors.Is(err, errors.Forbidden) || called {
				t.Fatalf("out-of-scope request: next=%v err=%v", called, err)
			}
		})
	}
}
