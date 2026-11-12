package user

import (
	"context"

	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/domain/meta"
)

type userHTTPExistingAccess struct {
	core   *appcrud.Application[*iamentity.User, int64]
	before map[int64]*iamentity.User
}

// User's business Lock/Unlock methods satisfy sync.Locker for go vet.
// This method-free view copies its data without treating status methods as locks.
type userHTTPState iamentity.User

func (access *userHTTPExistingAccess) capture(fn func(context.Context, *iamentity.User) error) func(context.Context, *iamentity.User) error {
	return func(ctx context.Context, item *iamentity.User) error {
		snapshot, err := meta.Clone(item)
		if err != nil {
			return err
		}
		access.before[item.ID] = snapshot
		return fn(ctx, item)
	}
}
