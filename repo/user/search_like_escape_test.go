package user

import (
	"context"
	"gochen/domain/spec"
	"testing"

	"gochen/testkit"
)

// TestSearchUsersLikeEscapesWildcards 回归 R7S1b-F03：搜索关键字中的 LIKE 通配符必须被转义，
// 且 SQL 侧显式声明 ESCAPE '!'。
func TestSearchUsersLikeEscapesWildcards(t *testing.T) {
	o := &fakeOrm{baseModel: &capturingModel{}, sessionModel: &capturingModel{}}
	r, err := NewUserRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewUserRepository: %v", err)
	}
	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.SearchUsers(ctx, "a%c_!", 10, spec.All()); err != nil {
		t.Fatalf("SearchUsers: %v", err)
	}

	where := o.baseModel.lastOpts.Where
	requireCondition(t, where, "(username LIKE ? ESCAPE '!' OR email LIKE ? ESCAPE '!')", "%a!%c!_!!%", "%a!%c!_!!%")
}
