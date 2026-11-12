package user_test

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	iamentity "gochen-iam/entity"
	"gochen-iam/router"
	svc "gochen-iam/service"
	usersvc "gochen-iam/service/user"
	"gochen-iam/tenant"
	ormrepo "gochen-runtime/db/orm/repo"
	runtimehttp "gochen-runtime/http"
	"gochen-runtime/http/nethttp"
	"gochen/auth/scoped"
	"gochen/contextx"
	"gochen/db/orm"
	"gochen/domain/meta"
	"gochen/domain/spec"
	"gochen/errors"
	"gorm.io/gorm"
)

func TestUserRoleBindingEntriesRejectBeforeResourceAccess(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	reads, writes := &atomic.Int64{}, &atomic.Int64{}
	if err := env.db.Callback().Query().Before("gorm:query").Register("user:binding:reads", func(*gorm.DB) { reads.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := env.db.Callback().Delete().Before("gorm:delete").Register("user:binding:writes", func(*gorm.DB) { writes.Add(1) }); err != nil {
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
	for _, ctx := range []context.Context{t.Context(), trace, userAssociationPrincipal(t, env.tenantID, "7", "platform", "role:api:write")} {
		if err := env.userService.RemoveRoleBinding(ctx, 99, 100); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("ordinary removal=%v", err)
		}
		if _, err := env.userService.UserRoleBindings(ctx, 99); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("ordinary projection=%v", err)
		}
	}
	for _, test := range []struct {
		ctx  context.Context
		code errors.ErrorCode
	}{
		{nil, errors.InvalidInput},
		{userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:write"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:read", "user:api:write", "user:api:manage"), errors.Forbidden},
		{userAssociationPrincipal(t, env.tenantID, "trace", "platform", "user:api:read", "user:api:write", "user:api:manage"), errors.Unauthorized},
	} {
		if err := env.userService.ExecuteRoleBindingRemovalHTTP(test.ctx, usersvc.UserRoleBindingInput{UserID: 99, BindingID: 100}); !errors.Is(err, test.code) {
			t.Fatalf("HTTP removal=%v want=%s", err, test.code)
		}
		if _, err := env.userService.ExecuteRoleBindingReadHTTP(test.ctx, 99); !errors.Is(err, test.code) {
			t.Fatalf("HTTP projection=%v want=%s", err, test.code)
		}
	}
	if reads.Load() != 0 || writes.Load() != 0 {
		t.Fatalf("denied reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

func TestUserRoleBindingRemovalKeepsAssociationAndGrantVisibility(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	bindings := []*iamentity.UserRoleBinding{
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: env.rootScopeID, Status: "active"},
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: 999, Status: "active"},
		{UserID: user.ID + 1, RoleID: role.ID, GrantScopeID: env.rootScopeID, Status: "active"},
	}
	for _, binding := range bindings {
		if err := env.db.Create(binding).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, binding := range bindings[1:] {
		if err := env.userService.RemoveRoleBinding(env.backgroundCtx, user.ID, binding.ID); !errors.Is(err, errors.Forbidden) {
			t.Fatalf("invalid association/grant binding=%d error=%v", binding.ID, err)
		}
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:write")
	ctx, err := scoped.WithDataScope(ctx, scoped.Filtered(999))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.userService.RemoveRoleBinding(ctx, user.ID, bindings[0].ID); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("outside user predicate=%v", err)
	}
	if err := env.userService.RemoveRoleBinding(env.backgroundCtx, user.ID, bindings[0].ID); err != nil {
		t.Fatal(err)
	}
	var remaining []iamentity.UserRoleBinding
	if err := env.db.Order("id").Find(&remaining).Error; err != nil || len(remaining) != 2 || remaining[0].ID != bindings[1].ID || remaining[1].ID != bindings[2].ID {
		t.Fatalf("unrelated bindings changed=%+v error=%v", remaining, err)
	}
}

func TestUserRoleBindingRemovalRechecksSelectedSnapshot(t *testing.T) {
	for _, column := range []string{"grant_scope_id", "user_id", "role_id", "status"} {
		t.Run(column, func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user, role := roleAssignmentTargets(t, env)
			binding := &iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: env.rootScopeID, Status: "active"}
			if err := env.db.Create(binding).Error; err != nil {
				t.Fatal(err)
			}
			injected := &atomic.Bool{}
			if err := env.db.Callback().Query().After("gorm:query").Register("user:binding:change", func(tx *gorm.DB) {
				if tx.Statement.Table == "roles" && injected.CompareAndSwap(false, true) {
					value := any(int64(999))
					if column == "status" {
						value = "inactive"
					}
					if err := env.db.Model(&iamentity.UserRoleBinding{}).Where("id = ?", binding.ID).UpdateColumn(column, value).Error; err != nil {
						tx.AddError(err)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := env.userService.RemoveRoleBinding(env.backgroundCtx, user.ID, binding.ID); !errors.Is(err, errors.Conflict) || !injected.Load() {
				t.Fatalf("stale %s snapshot deletion=%v", column, err)
			}
			var count int64
			if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("stale binding count=%d error=%v", count, err)
			}
		})
	}
}

func TestUserRoleBindingDeleteRepositoryAppliesBothResourceConditions(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	if err := env.db.Model(role).UpdateColumn("namespace_scope_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	binding := &iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: 1, Status: "active"}
	if err := env.db.Create(binding).Error; err != nil {
		t.Fatal(err)
	}
	selected, err := env.userRepo.GetRoleBinding(env.backgroundCtx, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	userCondition := spec.Eq(meta.ByDimension("scope"), int64(1))
	roleCondition := spec.Eq(meta.ByDimension("scope"), int64(2))
	if err := env.userRepo.RemoveAuthorizedRoleBinding(env.backgroundCtx, *selected, userCondition, userCondition); !errors.Is(err, errors.Forbidden) {
		t.Fatalf("role predicate ignored=%v", err)
	}
	if err := env.userRepo.RemoveAuthorizedRoleBinding(env.backgroundCtx, *selected, userCondition, roleCondition); err != nil {
		t.Fatal(err)
	}
}

func TestUserRoleBindingProjectionAndDeletionOnRealHTTP(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	user, role := roleAssignmentTargets(t, env)
	bindings := []*iamentity.UserRoleBinding{
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: env.rootScopeID, Status: "active"},
		{UserID: user.ID, RoleID: 777, GrantScopeID: env.rootScopeID, Status: "active"},
		{UserID: user.ID, RoleID: role.ID, GrantScopeID: 999, Status: "active"},
	}
	for _, binding := range bindings {
		if err := env.db.Create(binding).Error; err != nil {
			t.Fatal(err)
		}
	}
	routes, err := router.NewUserRoutes(env.userService)
	if err != nil {
		t.Fatal(err)
	}
	server := nethttp.NewServer(&runtimehttp.WebConfig{})
	if err := routes.RegisterRoutes(server.Group("/iam")); err != nil {
		t.Fatal(err)
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "platform", "user:api:read", "user:api:write", "user:api:manage")
	read := httptest.NewRecorder()
	server.Handler().ServeHTTP(read, httptest.NewRequest("GET", "/iam/users/99/role-bindings", nil).WithContext(ctx))
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"role_name":"assignment"`) || !strings.Contains(read.Body.String(), `"role_name":"已删除角色 #777"`) || strings.Contains(read.Body.String(), `"grant_scope_id":999`) || !strings.Contains(read.Body.String(), `"grant_scope_key":"tenant:`+env.tenantID+`"`) {
		t.Fatalf("HTTP projection status=%d body=%s", read.Code, read.Body.String())
	}
	deleted := httptest.NewRecorder()
	server.Handler().ServeHTTP(deleted, httptest.NewRequest("DELETE", "/iam/users/99/role-bindings/"+strconv.FormatInt(bindings[0].ID, 10), nil).WithContext(ctx))
	if deleted.Code != 200 || !strings.Contains(deleted.Body.String(), `"binding_id":`+strconv.FormatInt(bindings[0].ID, 10)) {
		t.Fatalf("HTTP deletion status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestUserRoleBindingDeletionFailureRollsBackActualSQLite(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(strconv.FormatBool(all), func(t *testing.T) {
			env := setupUserServiceTest(t)
			defer env.teardown(t)
			user, role := roleAssignmentTargets(t, env)
			var selected int64
			for _, scope := range []int64{1, env.rootScopeID} {
				binding := &iamentity.UserRoleBinding{UserID: user.ID, RoleID: role.ID, GrantScopeID: scope, Status: "active"}
				if err := env.db.Create(binding).Error; err != nil {
					t.Fatal(err)
				}
				selected = binding.ID
			}
			if err := env.db.Exec("CREATE TRIGGER reject_binding_delete BEFORE DELETE ON user_role_bindings WHEN OLD.grant_scope_id = " + strconv.FormatInt(env.rootScopeID, 10) + " BEGIN SELECT RAISE(ABORT, 'injected binding deletion'); END").Error; err != nil {
				t.Fatal(err)
			}
			var err error
			if all {
				err = env.userService.RemoveRole(env.backgroundCtx, user.ID, role.ID)
			} else {
				err = env.userService.RemoveRoleBinding(env.backgroundCtx, user.ID, selected)
			}
			if err == nil || !strings.Contains(err.Error(), "injected binding deletion") {
				t.Fatalf("injected deletion=%v", err)
			}
			var count int64
			if err := env.db.Model(&iamentity.UserRoleBinding{}).Count(&count).Error; err != nil || count != 2 {
				t.Fatalf("failed deletion count=%d error=%v", count, err)
			}
		})
	}
}

func TestUserRoleBindingSingleTenantAncestorProjectionWithScopedRoleSource(t *testing.T) {
	env := setupUserServiceTest(t)
	defer env.teardown(t)
	base, err := ormrepo.NewRepo[*iamentity.Role, int64](env.roleRepo.Orm(), "roles",
		ormrepo.WithResourceKind[*iamentity.Role, int64](svc.RoleResourceKind),
		ormrepo.WithSoftDeleteColumns[*iamentity.Role, int64]("deleted_at", ""),
		ormrepo.WithIsolation[*iamentity.Role, int64](ormrepo.IsolationCols{Column: "tenant_id"}),
		ormrepo.WithReadPredicate[*iamentity.Role, int64](func(ctx context.Context) (orm.Condition, error) {
			scope, ok := scoped.DataScopeFromContext(ctx)
			if ok && scope.Kind == scoped.ScopeFiltered {
				return orm.Condition{Expr: "namespace_scope_id IN ?", Args: []any{scope.ScopeIDs}}, nil
			}
			return orm.Condition{}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	env.roleRepo.Repo = base
	scopes := svc.NewScopeAuthorizer(env.scopeRepo, env.tenantRepo)
	service, err := usersvc.NewUserService(env.userRepo, env.groupRepo, env.roleRepo, scopes, svc.NewIAMAccess(scopes), nil)
	if err != nil {
		t.Fatal(err)
	}
	user := &iamentity.User{TenantID: env.tenantID, ManagedScopeID: env.rootScopeID, HomeTenantID: env.tenantID, HomeScopeID: env.rootScopeID, OwnerID: "owner", Username: "ancestor", Email: "ancestor@example.test"}
	user.ID = 99
	ancestor := &iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: 1, OwnerID: "platform", Name: "Ancestor role", Code: "ancestor", Permissions: []string{"user:api:read"}}
	ancestor.ID = 100
	unrelated := &iamentity.Role{TenantID: env.tenantID, NamespaceScopeID: 999, OwnerID: "owner", Name: "Hidden role", Code: "secret", Permissions: []string{"*:*:*"}}
	unrelated.ID = 101
	for _, item := range []any{user, ancestor, unrelated, &iamentity.UserRoleBinding{UserID: 99, RoleID: 100, GrantScopeID: 1, Status: "active"}, &iamentity.UserRoleBinding{UserID: 99, RoleID: 101, GrantScopeID: 1, Status: "active"}} {
		if err := env.db.Create(item).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx := userAssociationPrincipal(t, env.tenantID, "7", "department", "user:api:read", "user:api:manage")
	ctx = tenant.WithPolicy(ctx, tenant.Policy{Mode: tenant.ModeSingle, SingleTenantID: env.tenantID})
	ctx, err = scoped.WithDataScope(ctx, scoped.Filtered(env.rootScopeID))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ExecuteRoleBindingReadHTTP(ctx, 99)
	if err != nil || len(result) != 2 {
		t.Fatalf("single projection count=%d error=%v", len(result), err)
	}
	for _, detail := range result {
		if detail.RoleID == 100 {
			if detail.RoleName != "Ancestor role" || detail.RoleCode != "ancestor" || detail.NamespaceScopeID != 1 || detail.NamespaceScopeKey != "platform" || detail.GrantScopeKey != "platform" || len(detail.Permissions) != 1 {
				t.Fatalf("ancestor projection=%+v", detail)
			}
		} else if detail.RoleName != "不可见角色 #101" || detail.RoleCode != "" || detail.NamespaceScopeID != 0 || len(detail.Permissions) != 0 {
			t.Fatalf("unrelated namespace disclosed=%+v", detail)
		}
	}
	if err := env.db.Model(&iamentity.Tenant{}).Where("key = ?", env.tenantID).UpdateColumn("root_scope_id", 999).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := service.UserRoleBindings(ctx, 99); !errors.Is(err, errors.Internal) {
		t.Fatalf("drifted tenant root projection=%v", err)
	}
}
