package role

import (
	"context"
	"testing"

	"gochen/testkit"
)

// TestSearchRolesLikeEscapesWildcards 回归 R7S1b-F03：搜索关键字中的 LIKE 通配符必须被转义，
// 且 SQL 侧显式声明 ESCAPE '!'。
func TestSearchRolesLikeEscapesWildcards(t *testing.T) {
	o := &fakeOrm{baseRoleModel: &capturingModel{}}
	r, err := NewRoleRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewRoleRepository: %v", err)
	}
	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.SearchRoles(ctx, "a%c_!", 10); err != nil {
		t.Fatalf("SearchRoles: %v", err)
	}

	where := o.baseRoleModel.lastOpts.Where
	requireCondition(t, where, "(name LIKE ? ESCAPE '!' OR description LIKE ? ESCAPE '!')", "%a!%c!_!!%", "%a!%c!_!!%")
}
