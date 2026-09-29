package iam

import (
	"gochen/observe/logging"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	iammw "gochen-iam/middleware"
	iamservice "gochen-iam/service"
	"gochen-runtime/db/orm/lite"
	"gochen-runtime/db/sql/stdsql"
	"gochen-runtime/di"
	"gochen-runtime/di/basic"
	auth "gochen-runtime/host/authz"
	"gochen-runtime/host/module"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/db"
	"gochen/db/orm"
	"gochen/gen"
	"gochen/testkit"
)

func TestIAMModulePublicFeaturesExposeOnlyTenantMode(t *testing.T) {
	authConfig := iammw.DefaultAuthConfigForEnvironment("test")
	instance, err := NewModule(&moduleTestDatabase{}, logging.NewNoopLogger())
	if err != nil {
		t.Fatalf("NewModule(database) error: %v", err)
	}
	container := basic.New()
	if err := instance.Init(module.NewModuleInitOptions(container, container, container, ModuleAuthConfig(authConfig))); err != nil {
		t.Fatalf("IAM module Init error: %v", err)
	}
	provider, ok := instance.(module.IPublicFeatureProvider)
	if !ok {
		t.Fatal("expected IAM module to implement IPublicFeatureProvider")
	}
	features := provider.PublicFeatures()
	if len(features) != 1 || features[0].Key != "tenant_mode" || features[0].Value != "single" {
		t.Fatalf("unexpected public features: %#v", features)
	}
}

func TestNewModuleRejectsNilDatabase(t *testing.T) {
	if _, err := NewModule(nil, logging.NewNoopLogger()); err == nil {
		t.Fatal("expected nil database to be rejected")
	}
}

// TestNewModuleRegistersIAMPermissionCatalog 守住权限目录登记：
// 路由装配期的 PermissionMiddleware 只登记路由拦截的码，
// 目录一旦不再登记，read/write/delete 与 menu:view 等码会被角色校验判为“未知权限”。
func TestNewModuleRegistersIAMPermissionCatalog(t *testing.T) {
	if _, err := NewModule(&moduleTestDatabase{}, logging.NewNoopLogger()); err != nil {
		t.Fatalf("NewModule(database) error: %v", err)
	}

	for _, code := range []string{
		iamservice.UserPermissionSet.Code(iammw.ActionRead),
		iamservice.MenuPermissionSet.Code(iammw.ActionRead),
		iamservice.RolePermissionSet.Code(iammw.ActionDelete),
	} {
		if !iammw.HasRequiredPermission(code) {
			t.Fatalf("expected IAM catalog permission %q in strict permission registry", code)
		}
	}
}

type moduleTestDatabase struct{ db.IDatabase }

func TestIAMModulesBindIndependentAuthResolvers(t *testing.T) {
	var configs []*iammw.AuthConfig
	var resolvers []*iamservice.AuthContextResolver
	for range 2 {
		container := basic.New()
		register := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		database, err := stdsql.New(db.DBConfig{Driver: "sqlite3", Database: ":memory:"})
		register(err)
		t.Cleanup(func() { register(database.Close()) })
		engine, err := lite.New(database)
		register(err)
		register(di.RegisterInstance[orm.IOrm](container, engine))
		register(di.RegisterInstance[gen.IGenerator[int64]](container, testkit.GeneratorFunc[int64](func() (int64, error) { return 1, nil })))
		register(di.RegisterInstance[scoped.IResourceResolver](container, auth.NewRegistry()))
		register(di.RegisterInstance[logging.ILogger](container, logging.NewNoopLogger()))
		config := iammw.DefaultAuthConfigForEnvironment("test")
		register(di.RegisterInstance[*iammw.AuthConfig](container, config))
		instance, err := NewModule(database, logging.NewNoopLogger())
		register(err)
		register(instance.Init(module.NewModuleInitOptions(container, container, container, ModuleAuthConfig(config))))
		resolver, err := di.Resolve[*iamservice.AuthContextResolver](container)
		register(err)
		configs = append(configs, config)
		resolvers = append(resolvers, resolver)
	}
	if resolvers[0] == resolvers[1] {
		t.Fatal("independent modules share an auth resolver")
	}
	for i := range configs {
		if configs[i].ContextResolver != resolvers[i] {
			t.Fatalf("module %d did not retain its own resolver", i)
		}
	}
}

func TestIAMModuleRejectsDifferentRegisteredAuthConfig(t *testing.T) {
	container := basic.New()
	if err := di.RegisterInstance[*iammw.AuthConfig](container, iammw.DefaultAuthConfigForEnvironment("test")); err != nil {
		t.Fatal(err)
	}
	instance, err := NewModule(&moduleTestDatabase{}, logging.NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Init(module.NewModuleInitOptions(container, container, container, ModuleAuthConfig(iammw.DefaultAuthConfigForEnvironment("test")))); err == nil {
		t.Fatal("different application and module configs must be rejected")
	}
}

func TestIAMModuleAuthMiddlewareSkipsAnonymousRoutesAtAnyBasePath(t *testing.T) {
	t.Setenv("AUTH_SECRET", "iam-module-route-test-secret")
	t.Setenv("APP_ENV", "test")
	middleware := iamModuleAuthMiddleware(iammw.DefaultAuthConfigForEnvironment("test"))
	for _, path := range []string{
		"/api/iam/auth/login",
		"/custom-api/identity/auth/register/",
		"/api/v1/iam/auth/forgot-password",
		"/api/iam/auth/logout",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
			request.AddCookie(&http.Cookie{Name: iammw.AccessTokenCookieName, Value: "stale-token"})
			ctx, err := nethttp.NewBaseContext(httptest.NewRecorder(), request)
			if err != nil {
				t.Fatalf("NewBaseContext: %v", err)
			}
			called := false
			if err := middleware(ctx, func() error { called = true; return nil }); err != nil {
				t.Fatalf("anonymous route returned error: %v", err)
			}
			if !called {
				t.Fatal("anonymous route did not reach handler")
			}
		})
	}
}

func TestIAMAnonymousAuthPathDoesNotSkipProtectedRoutes(t *testing.T) {
	for _, path := range []string{
		"/api/iam/auth/refresh",
		"/api/identity/login",
	} {
		if isIAMAnonymousAuthPath(path) {
			t.Fatalf("protected path was treated as anonymous: %s", path)
		}
	}
}
