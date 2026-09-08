package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	appaccess "gochen/auth/scoped"
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

func (r *crudApplicationRepoStub) ResolveResourceByID(context.Context, int64) (appaccess.Resource, error) {
	return appaccess.Resource{Kind: "iam.user", ID: "11", ManagedScopeID: 17}, nil
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

func TestCRUDApplication_WrapsConstraint(t *testing.T) {
	repo := &crudApplicationRepoStub{}
	app, err := NewCRUDApplication[*iamentity.User, int64](repo, repo)
	require.NoError(t, err)

	ctx := context.Background()
	constraint := appaccess.WriteConstraint{
		Resources: []appaccess.ResourceConstraint{{
			Kind:           "iam.user",
			ResourceID:     "11",
			Revision:       "3",
			ManagedScopeID: 17,
		}},
	}

	user := &iamentity.User{
		TenantID:       "tenant-1",
		HomeTenantID:   "tenant-1",
		HomeScopeID:    17,
		ManagedScopeID: 17,
		OwnerID:        "owner-1",
		Username:       "user-1",
		Email:          "user-1@example.com",
		Password:       "secret1",
		Status:         "active",
	}
	user.SetID(11)

	require.NoError(t, app.CreateWithConstraint(ctx, user, constraint))
	require.Equal(t, constraint.Resources, repo.lastCreate.Unwrap().Resources)

	require.NoError(t, app.UpdateWithConstraint(ctx, user, constraint))
	require.Equal(t, constraint.Resources, repo.lastUpdate.Unwrap().Resources)

	require.NoError(t, app.DeleteWithConstraint(ctx, 11, constraint))
	require.Equal(t, constraint.Resources, repo.lastDelete.Unwrap().Resources)
}
