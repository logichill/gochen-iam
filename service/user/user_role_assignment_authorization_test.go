package user_test

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	iamauth "gochen-iam/auth"
	iamentity "gochen-iam/entity"
	"gochen-iam/router"
	usersvc "gochen-iam/service/user"
	iamtenant "gochen-iam/tenant"
	hostauthz "gochen-runtime/host/authz"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/errors"
	"gorm.io/gorm"
)

func roleAssignmentTargets(t *testing.T, env *userServiceTestEnv) (*iamentity.User, *iamentity.Role) {
	t.Helper()
	user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: 1, HomeTenantID: env.tenantID, HomeScopeID: 1, OwnerID: "owner", Username: "assignment", Email: "assignment@example.test"}
	user.ID = 99
	role := &iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: 1, OwnerID: "owner", Name: "assignment", Status: "active"}
	role.ID = 100
	for _, item := range []any{user, role} {
		if err := env.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	return user, role
}

func TestUserRoleAssignmentRejectsBeforeAllResourceReads(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	reads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:assignment:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	trace, err := contextx.WithTenantID(t.Context(), env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err = contextx.WithUserID(trace, "7")
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read")} {
		if err := env.userService.AssignRole(ctx, 99, 100); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("ordinary denial=%v", err)
		}
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{
		{nil, errors.InvalidInput},
		{userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:write", "user:api:manage"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "trace", "tenant", "user:api:write", "user:api:manage"), errors.Unauthorized},
	} {
		if err := env.userService.ExecuteRoleAssignmentHTTP(test.ctx, usersvc.UserRoleAssignmentInput{UserID: 99, RoleID: 100}); !errors.Is(err, test.code) {
			t.Fatalf("HTTP denial=%v, want %s", err, test.code)
		}
	}
	if reads.Load() != 0 {
		t.Fatalf("denied assignment read %d resources", reads.Load())
	}
}

func TestUserRoleAssignmentPreservesScopeAndStatusConstraints(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write", "user:api:manage")
	for _, change := range []struct {
		column string
		value  any
		code   errors.ErrorCode
	}{
		{"status", "inactive", errors.Validation},
		{"namespace_scope_id", int64(999), errors.Forbidden},
		{"tenant_id", "other", errors.NotFound},
	} {
		if err := env.db.Model(role).UpdateColumn(change.column, change.value).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.userService.AssignRole(ctx, user.ID, role.ID); !errors.Is(err, change.code) {
			t.Fatalf("changed %s assignment=%v, want %s", change.column, err, change.code)
		}
		if err := env.db.Model(role).Updates(map[string]any{"status": "active", "namespace_scope_id": 1, "tenant_id": env.tenantID}).Error; err != nil {
			t.Fatal(err)
		}
	}
	nonRoot := int64(1)
	single := iamtenant.WithPolicy(ctx, iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
	if err := env.userService.AssignRoleBinding(single, user.ID, role.ID, &nonRoot); !errors.Is(err, errors.InvalidInput) {
		t.Fatalf("single accepted non-root grant=%v", err)
	}
	if err := env.db.Model(role).UpdateColumn("namespace_scope_id", env.rootScopeID).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.userService.AssignRoleBinding(env.backgroundCtx, user.ID, role.ID, &nonRoot); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("System lost namespace coverage check=%v", err)
	}
	if err := env.db.Model(role).UpdateColumn("namespace_scope_id", 1).Error; err != nil {
		t.Fatal(err)
	}
	rootCtx, err := hostauthz.WithPrincipal(ctx, hostauthz.Principal{SubjectID: "7", ActiveScopeID: env.rootScopeID, Permissions: []string{"user:api:write"}})
	if err != nil {
		t.Fatal(err)
	}
	rootCtx = iamauth.BindActiveScopeContext(rootCtx, env.rootScopeID, "tenant")
	rootCtx, err = scoped.WithDataScope(rootCtx, scoped.Filtered(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.userService.AssignRoleBinding(rootCtx, user.ID, role.ID, &nonRoot); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("active scope granted its ancestor=%v", err)
	}
	if err := env.db.Model(role).UpdateColumn("owner_id", "platform").Error; err != nil {
		t.Fatal(err)
	}
	if err := env.userService.AssignRoleBinding(rootCtx, user.ID, role.ID, &env.rootScopeID); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("tenant identity assigned platform-owned role=%v", err)
	}
	var count int64
	if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("denied constraints created bindings=%d error=%v", count, err)
	}
	if err := env.userService.ExecuteRoleAssignmentHTTP(single, usersvc.UserRoleAssignmentInput{UserID: user.ID, RoleID: role.ID}); err != nil {
		t.Fatalf("single assignment=%v", err)
	}
	var binding iamentity.UserRoleBinding
	if err := env.db.First(&binding).Error; err != nil || binding.UserID != user.ID || binding.RoleID != role.ID || binding.GrantScopeID != env.rootScopeID {
		t.Fatalf("single stored binding=%+v error=%v", binding, err)
	}
}

func TestUserRoleAssignmentFreezesResourcesAndRequestedScope(t *testing.T) {
	for _, table := range []string{"users", "roles", "scope_intent"} {
		t.Run(table, func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user, role := roleAssignmentTargets(t, env)
			target := env.rootScopeID
			injected := &atomic.Bool{}
			if err := env.db.Callback().Query().After("gorm:query").Register("user:assignment:change", func(tx *gorm.DB) {
				if (tx.Statement.Table == table || table == "scope_intent" && tx.Statement.Table == "users") && injected.CompareAndSwap(false, true) {
					if table == "scope_intent" {
						target = 999
					} else if err := env.db.Table(table).Where("id IN ?", []int64{user.ID, role.ID}).UpdateColumn("version", gorm.Expr("version + 1")).Error; err != nil {
						tx.AddError(err)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			err := env.userService.AssignRoleBinding(env.backgroundCtx, user.ID, role.ID, &target)
			var count int64
			if table == "scope_intent" {
				if err != nil || target != 999 {
					t.Fatalf("scope intent changed execution=%v, target=%d", err, target)
				}
				var binding iamentity.UserRoleBinding
				if err := env.db.First(&binding).Error; err != nil || binding.GrantScopeID != env.rootScopeID {
					t.Fatalf("stored untrusted scope=%+v error=%v", binding, err)
				}
			} else {
				if !errors.Is(err, errors.Conflict) || !injected.Load() {
					t.Fatalf("stale %s assignment=%v", table, err)
				}
				if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("stale fact created bindings=%d error=%v", count, err)
				}
			}
		})
	}
}

func TestUserRoleAssignmentOnRealHTTP(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/iam/users/99/roles", "/iam/users/99/role-bindings"} {
		ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write", "user:api:manage")
		body := `{"role_id":100,"grant_scope_id":` + strconv.FormatInt(env.rootScopeID, 10) + `}`
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"user_id":99`) || !strings.Contains(recorder.Body.String(), `"role_id":100`) {
			t.Fatalf("actual %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
		var binding iamentity.UserRoleBinding
		if err := env.db.First(&binding).Error; err != nil || binding.UserID != user.ID || binding.RoleID != role.ID || binding.GrantScopeID != env.rootScopeID {
			t.Fatalf("HTTP binding=%+v error=%v", binding, err)
		}
		if err := env.db.Where("user_id = ?", user.ID).Delete(&iamentity.UserRoleBinding{}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUserRoleAssignmentDeclaresActualScopeSources(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	binding, err := env.userService.RoleAssignmentAuthorizationBinding()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"role", "binding", "scope", "visibility", "tenant", "root"}
	if len(binding.Resources) != len(names) {
		t.Fatalf("assignment scope sources=%+v", binding.Resources)
	}
	for i, name := range names {
		if binding.Resources[i].Name != name || binding.Resources[i].Plan == nil || binding.Resources[i].ConditionPath == "" {
			t.Fatalf("missing actual source %s=%+v", name, binding.Resources[i])
		}
	}
	user, role := roleAssignmentTargets(t, env)
	tenantReads := &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:assignment:root-branch", func(tx *gorm.DB) {
		if tx.Statement.Table == "tenants" {
			tenantReads.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.userService.AssignRoleBinding(env.backgroundCtx, user.ID, role.ID, &env.rootScopeID); err != nil {
		t.Fatal(err)
	}
	if tenantReads.Load() != 0 {
		t.Fatalf("ordinary assignment loaded unselected tenant root %d times", tenantReads.Load())
	}
}

func TestUserRoleAssignmentKeepsNonpositiveGrantDefaults(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	zero, negative := int64(0), int64(-1)
	for _, single := range []bool{false, true} {
		ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")
		expected := int64(1)
		if single {
			ctx = iamtenant.WithPolicy(ctx, iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
			expected = env.rootScopeID
		}
		for _, grant := range []*int64{nil, &zero, &negative} {
			if err := env.userService.AssignRoleBinding(ctx, user.ID, role.ID, grant); err != nil {
				t.Fatalf("single=%v grant=%v assignment=%v", single, grant, err)
			}
			var binding iamentity.UserRoleBinding
			if err := env.db.First(&binding).Error; err != nil || binding.GrantScopeID != expected {
				t.Fatalf("single=%v default grant=%+v error=%v", single, binding, err)
			}
			if err := env.db.Where("user_id = ?", user.ID).Delete(&iamentity.UserRoleBinding{}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestUserRoleAssignmentRechecksAuthorityAndRollsBack(t *testing.T) {
	for _, failure := range []string{"visibility", "tenant_root", "binding_write"} {
		t.Run(failure, func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user, role := roleAssignmentTargets(t, env)
			injected := &atomic.Bool{}
			code := errors.Forbidden
			if failure == "binding_write" {
				code = errors.Database
				if err := env.db.Callback().Create().After("gorm:create").Register("user:assignment:write-fault", func(tx *gorm.DB) {
					if tx.Statement.Table == "user_role_bindings" && injected.CompareAndSwap(false, true) {
						tx.AddError(errors.NewCode(errors.Database, "binding write fault"))
					}
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				if failure == "tenant_root" {
					code = errors.Internal
				}
				if err := env.db.Callback().Query().After("gorm:query").Register("user:assignment:authority-change", func(tx *gorm.DB) {
					if failure == "visibility" && tx.Statement.Table == "scope_visibility_map" && injected.CompareAndSwap(false, true) {
						if err := env.db.Where("viewer_scope_id = ? AND target_scope_id = ?", int64(1), env.rootScopeID).Delete(&iamentity.ScopeVisibility{}).Error; err != nil {
							tx.AddError(err)
						}
					}
					if failure == "tenant_root" && tx.Statement.Table == "scopes" && injected.CompareAndSwap(false, true) {
						if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", env.tenantID).UpdateColumn("root_scope_id", int64(1)).Error; err != nil {
							tx.AddError(err)
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := env.backgroundCtx
			if failure == "tenant_root" {
				ctx = iamtenant.WithPolicy(ctx, iamtenant.Policy{Mode: iamtenant.ModeSingle, SingleTenantID: env.tenantID})
			}
			err := env.userService.AssignRoleBinding(ctx, user.ID, role.ID, &env.rootScopeID)
			if !injected.Load() || !errors.Is(err, code) {
				t.Fatalf("%s assignment=%v, want %s", failure, err, code)
			}
			var count int64
			if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("%s persisted binding count=%d error=%v", failure, count, err)
			}
		})
	}
}
