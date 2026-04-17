package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	appaccess "gochen/app/access"
)

type crudApplicationRepoStub struct {
	lastCreate iamaccess.WriteConstraint
	lastUpdate iamaccess.WriteConstraint
	lastDelete iamaccess.WriteConstraint
}

func (r *crudApplicationRepoStub) Create(context.Context, *iamentity.User) error { return nil }

func (r *crudApplicationRepoStub) Update(context.Context, *iamentity.User) error { return nil }

func (r *crudApplicationRepoStub) Delete(context.Context, int64) error { return nil }

func (r *crudApplicationRepoStub) Get(context.Context, int64) (*iamentity.User, error) {
	return &iamentity.User{}, nil
}

func (r *crudApplicationRepoStub) List(context.Context, int, int) ([]*iamentity.User, error) {
	return nil, nil
}

func (r *crudApplicationRepoStub) Count(context.Context) (int64, error) { return 0, nil }

func (r *crudApplicationRepoStub) Exists(context.Context, int64) (bool, error) { return false, nil }

func (r *crudApplicationRepoStub) ResolveResourceByID(context.Context, int64) (appaccess.ResourceBoundary, error) {
	return appaccess.ResourceBoundary{Kind: "iam.user", ID: "11", ManagedScopeID: 17}, nil
}

func (r *crudApplicationRepoStub) CreateWithConstraint(ctx context.Context, entity *iamentity.User, constraint iamaccess.WriteConstraint) error {
	r.lastCreate = constraint
	return nil
}

func (r *crudApplicationRepoStub) UpdateWithConstraint(ctx context.Context, entity *iamentity.User, constraint iamaccess.WriteConstraint) error {
	r.lastUpdate = constraint
	return nil
}

func (r *crudApplicationRepoStub) DeleteWithConstraint(ctx context.Context, id int64, constraint iamaccess.WriteConstraint) error {
	r.lastDelete = constraint
	return nil
}

func TestCRUDApplication_WrapsConstraintMetadataFromContext(t *testing.T) {
	repo := &crudApplicationRepoStub{}
	app, err := NewCRUDApplication[*iamentity.User, int64](repo, repo)
	require.NoError(t, err)

	ctx := appaccess.WithConstraintMetadata(context.Background(), appaccess.ConstraintMetadata{
		DecisionID:      "decision-1",
		SnapshotVersion: "snap-2",
		Consistency:     "strong",
	})
	constraint := appaccess.WriteConstraint{
		Resources: []appaccess.ResourceConstraint{{
			Kind:           "iam.user",
			ResourceID:     "11",
			Revision:       "3",
			ManagedScopeID: 17,
		}},
	}

	require.NoError(t, app.CreateWithConstraint(ctx, &iamentity.User{}, constraint))
	require.Equal(t, constraint, repo.lastCreate.Unwrap())
	require.Equal(t, "decision-1", repo.lastCreate.Metadata.DecisionID)
	require.Equal(t, "snap-2", repo.lastCreate.Metadata.SnapshotVersion)
	require.Equal(t, "strong", repo.lastCreate.Metadata.Consistency)

	require.NoError(t, app.UpdateWithConstraint(ctx, &iamentity.User{}, constraint))
	require.Equal(t, constraint, repo.lastUpdate.Unwrap())
	require.Equal(t, "decision-1", repo.lastUpdate.Metadata.DecisionID)

	require.NoError(t, app.DeleteWithConstraint(ctx, 11, constraint))
	require.Equal(t, constraint, repo.lastDelete.Unwrap())
	require.Equal(t, "decision-1", repo.lastDelete.Metadata.DecisionID)
}
