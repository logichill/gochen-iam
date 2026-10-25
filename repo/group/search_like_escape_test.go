package group

import (
	"context"
	"testing"

	"gochen/testkit"
)

// TestSearchGroupsLikeEscapesWildcards 回归 R7S1b-F03：搜索关键字中的 LIKE 通配符必须被转义，
// 且 SQL 侧显式声明 ESCAPE '!'。
func TestSearchGroupsLikeEscapesWildcards(t *testing.T) {
	o := &fakeOrm{baseModel: &capturingModel{}, sessionModel: &capturingModel{}}
	r, err := NewGroupRepository(o, testkit.NewInt64Sequence(1))
	if err != nil {
		t.Fatalf("NewGroupRepository: %v", err)
	}
	ctx := withTenantPrincipal(t, context.Background(), "tenant-a")
	if _, err := r.SearchGroups(ctx, "a%c_!", 10); err != nil {
		t.Fatalf("SearchGroups: %v", err)
	}

	where := o.baseModel.lastOpts.Where
	requireCondition(t, where, "(name LIKE ? ESCAPE '!' OR description LIKE ? ESCAPE '!')", "%a!%c!_!!%", "%a!%c!_!!%")
}
