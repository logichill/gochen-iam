package scope

import (
	"context"
	"strings"

	iamentity "gochen-iam/entity"
	"gochen/db/orm"
	db "gochen/db/orm/repo"
	"gochen/errorx"
	"gochen/ident"
)

type ScopeRepo struct {
	*db.Repo[*iamentity.Scope, int64]
}

func NewScopeRepository(o orm.IOrm) (*ScopeRepo, error) {
	base, err := db.NewRepo[*iamentity.Scope, int64](
		o,
		"scopes",
		db.WithIDGenerator[*iamentity.Scope, int64](ident.DefaultInt64Generator()),
	)
	if err != nil {
		return nil, err
	}
	return &ScopeRepo{Repo: base}, nil
}

func (r *ScopeRepo) Get(ctx context.Context, id int64) (*iamentity.Scope, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var scope iamentity.Scope
	err = model.First(ctx, &scope, orm.WithWhere("id = ? AND deleted_at IS NULL", id))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "scope 不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询 scope 失败")
	}
	return &scope, nil
}

func (r *ScopeRepo) FindByKey(ctx context.Context, key string) (*iamentity.Scope, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var scope iamentity.Scope
	err = model.First(ctx, &scope, orm.WithWhere("key = ? AND deleted_at IS NULL", strings.TrimSpace(key)))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "scope 不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询 scope 失败")
	}
	return &scope, nil
}

func (r *ScopeRepo) FindPlatform(ctx context.Context) (*iamentity.Scope, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var scope iamentity.Scope
	err = model.First(ctx, &scope, orm.WithWhere("type = ? AND deleted_at IS NULL", iamentity.ScopeTypePlatform))
	if err != nil {
		if errorx.Is(err, errorx.NotFound) {
			return nil, errorx.New(errorx.NotFound, "platform scope 不存在")
		}
		return nil, errorx.Wrap(err, errorx.Database, "查询 platform scope 失败")
	}
	return &scope, nil
}

func (r *ScopeRepo) ScopeCovers(ctx context.Context, ancestorID, descendantID int64) (bool, error) {
	ancestor, err := r.Get(ctx, ancestorID)
	if err != nil {
		return false, err
	}
	descendant, err := r.Get(ctx, descendantID)
	if err != nil {
		return false, err
	}
	return ancestor.Covers(descendant), nil
}
