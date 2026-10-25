package service

import (
	"context"
	"testing"

	iamentity "gochen-iam/entity"
	appcrud "gochen/app/crud"
	"gochen/errors"
)

type transactionalCRUDRepo struct {
	crudApplicationRepoStub
	writes  int
	txCalls int
}

func (r *transactionalCRUDRepo) Create(context.Context, *iamentity.User) error {
	r.writes++
	return nil
}

func (r *transactionalCRUDRepo) WithinTx(ctx context.Context, fn func(context.Context) error) error {
	r.txCalls++
	before := r.writes
	if err := fn(ctx); err != nil {
		r.writes = before
		return err
	}
	return nil
}

func TestCRUDApplicationRollsBackWhenAfterCreateFails(t *testing.T) {
	repo := &transactionalCRUDRepo{}
	app, err := NewCRUDApplication[*iamentity.User, int64](repo, repo, &appcrud.Options[*iamentity.User, int64]{Config: &appcrud.ServiceConfig{AutoValidate: false}, Hooks: &appcrud.Hooks[*iamentity.User, int64]{
		Create: appcrud.Stage[*iamentity.User]{
			After: func(context.Context, *iamentity.User) error {
				return errors.NewCode(errors.Database, "scope write failed")
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Create(context.Background(), &iamentity.User{}); err == nil {
		t.Fatal("expected hook failure")
	}
	if repo.txCalls != 1 || repo.writes != 0 {
		t.Fatalf("transaction calls=%d, committed writes=%d; failed hook must roll back create", repo.txCalls, repo.writes)
	}
	if app.Repository() != repo {
		t.Fatal("application must retain original repository capabilities")
	}
}

func TestCRUDApplicationDoesNotInventTransactionCapability(t *testing.T) {
	repo := &crudApplicationRepoStub{}
	app, err := NewCRUDApplication[*iamentity.User, int64](repo, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.Repository().(appcrud.ITransactional); ok {
		t.Fatal("nontransactional repository must remain nontransactional")
	}
}
