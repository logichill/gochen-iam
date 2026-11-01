package role

import (
	"testing"

	"gochen/domain/spec"
)

func TestRoleRepositoryUpdateReturnsPersistedVersion(t *testing.T) {
	env := setupRoleBulkTest(t)
	defer env.teardown(t)
	role := env.createTestRole(t, "version-round-trip")
	initial := role.Version
	for _, description := range []string{"updated", "updated-again"} {
		role.Description = description
		if err := env.roleRepo.Update(env.backgroundCtx, role, spec.All()); err != nil {
			t.Fatal(err)
		}
		initial++
		stored, err := env.roleRepo.Get(env.backgroundCtx, role.ID, spec.All())
		if err != nil {
			t.Fatal(err)
		}
		if role.Version != initial || stored.Version != role.Version || !stored.UpdatedAt.Equal(role.UpdatedAt) {
			t.Fatalf("caller version/time differs from persistence: caller=%d stored=%d expected=%d", role.Version, stored.Version, initial)
		}
	}
}
