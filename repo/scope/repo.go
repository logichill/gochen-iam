package scope

import (
	"context"
	"sort"
	"strings"
	"sync"

	iamaccess "gochen-iam/access"
	iamentity "gochen-iam/entity"
	assocguard "gochen-iam/repo/internal/guard"
	"gochen/db/orm"
	"gochen/db/orm/repo"
	"gochen/errors"
	"gochen/ident"
)

type ScopeRepo struct {
	*repo.Repo[*iamentity.Scope, int64]

	rebuildMu sync.Mutex
}

func NewScopeRepository(o orm.IOrm, idGenerator ident.IGenerator[int64]) (*ScopeRepo, error) {
	base, err := repo.NewRepo[*iamentity.Scope, int64](
		o,
		"scopes",
		repo.WithIDGenerator[*iamentity.Scope, int64](idGenerator),
		repo.WithResourceKind[*iamentity.Scope, int64]("iam.scope"),
		repo.WithSoftDeleteColumns[*iamentity.Scope, int64]("deleted_at", ""),
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
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "scope 不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询 scope 失败")
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
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "scope 不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询 scope 失败")
	}
	return &scope, nil
}

func (r *ScopeRepo) List(ctx context.Context) ([]*iamentity.Scope, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var scopes []*iamentity.Scope
	if err := model.Find(ctx, &scopes,
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithOrderBy("depth", false),
		orm.WithOrderBy("id", false),
	); err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询 scope 列表失败")
	}
	return scopes, nil
}

func (r *ScopeRepo) CountChildren(ctx context.Context, parentID int64) (int64, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return 0, err
	}
	count, err := model.Count(ctx,
		orm.WithWhere("parent_id = ? AND deleted_at IS NULL", parentID),
	)
	if err != nil {
		return 0, errors.Wrap(err, errors.Database, "统计子授权域失败")
	}
	return count, nil
}

func (r *ScopeRepo) FindPlatform(ctx context.Context) (*iamentity.Scope, error) {
	model, err := r.ModelFor(ctx)
	if err != nil {
		return nil, err
	}
	var scope iamentity.Scope
	err = model.First(ctx, &scope, orm.WithWhere("type = ? AND deleted_at IS NULL", iamentity.ScopeTypePlatform))
	if err != nil {
		if errors.Is(err, errors.NotFound) {
			return nil, errors.NewCode(errors.NotFound, "platform scope 不存在")
		}
		return nil, errors.Wrap(err, errors.Database, "查询 platform scope 失败")
	}
	return &scope, nil
}

func (r *ScopeRepo) ScopeCovers(ctx context.Context, ancestorID, descendantID int64) (bool, error) {
	if ancestorID <= 0 || descendantID <= 0 {
		return false, nil
	}
	visibleScopeIDs, err := r.VisibleScopeIDs(ctx, ancestorID)
	if err != nil {
		return false, err
	}
	for _, scopeID := range visibleScopeIDs {
		if scopeID == descendantID {
			return true, nil
		}
	}
	return false, nil
}

func (r *ScopeRepo) VisibleScopeIDs(ctx context.Context, viewerScopeID int64) ([]int64, error) {
	if viewerScopeID <= 0 {
		return nil, nil
	}
	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.ScopeVisibility](),
		Table:        "scope_visibility_map",
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.Database, "初始化 scope_visibility_map 模型失败")
	}
	var rows []*iamentity.ScopeVisibility
	if err := model.Find(ctx, &rows,
		orm.WithWhere("viewer_scope_id = ?", viewerScopeID),
		orm.WithOrderBy("distance", false),
		orm.WithOrderBy("target_scope_id", false),
	); err != nil {
		return nil, errors.Wrap(err, errors.Database, "查询 scope_visibility_map 失败")
	}
	ids := make([]int64, 0, len(rows))
	seen := make(map[int64]struct{}, len(rows))
	for _, row := range rows {
		if row == nil || row.TargetScopeID <= 0 {
			continue
		}
		if _, ok := seen[row.TargetScopeID]; ok {
			continue
		}
		seen[row.TargetScopeID] = struct{}{}
		ids = append(ids, row.TargetScopeID)
	}
	return ids, nil
}

// RebuildVisibilityMap 重建 scope 可见性投影。
//
// 并发语义：使用 process-local mutex 串行化 rebuild，防止同一进程内多个请求
// 交错触发 TRUNCATE-INSERT 造成 visibility map 进入不一致状态。
// 注：多进程部署仍需在上层通过 DB advisory lock 或调度器保证单写者。
func (r *ScopeRepo) RebuildVisibilityMap(ctx context.Context) error {
	r.rebuildMu.Lock()
	defer r.rebuildMu.Unlock()

	scopeModel, err := r.ModelFor(ctx)
	if err != nil {
		return err
	}
	var scopes []*iamentity.Scope
	if err := scopeModel.Find(ctx, &scopes,
		orm.WithWhere("deleted_at IS NULL"),
		orm.WithOrderBy("depth", false),
		orm.WithOrderBy("id", false),
	); err != nil {
		return errors.Wrap(err, errors.Database, "查询 scope 列表失败")
	}

	scopeByID := make(map[int64]*iamentity.Scope, len(scopes))
	for _, scope := range scopes {
		if scope == nil || scope.ID <= 0 {
			continue
		}
		scopeByID[scope.ID] = scope
	}

	rows := make([]*iamentity.ScopeVisibility, 0, len(scopeByID)*2)
	for _, target := range scopes {
		if target == nil || target.ID <= 0 {
			continue
		}
		current := target
		distance := 0
		for current != nil && current.ID > 0 {
			rows = append(rows, &iamentity.ScopeVisibility{
				ViewerScopeID: current.ID,
				TargetScopeID: target.ID,
				Distance:      distance,
			})
			if current.ParentID == nil || *current.ParentID <= 0 {
				break
			}
			current = scopeByID[*current.ParentID]
			distance++
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ViewerScopeID != rows[j].ViewerScopeID {
			return rows[i].ViewerScopeID < rows[j].ViewerScopeID
		}
		return rows[i].TargetScopeID < rows[j].TargetScopeID
	})

	engine := r.Orm()
	if session, ok := orm.SessionFromContext(ctx); ok && session != nil {
		engine = session
	}
	model, err := engine.Model(&orm.ModelMeta{
		ModelFactory: orm.NewModelFactory[iamentity.ScopeVisibility](),
		Table:        "scope_visibility_map",
	})
	if err != nil {
		return errors.Wrap(err, errors.Database, "初始化 scope_visibility_map 模型失败")
	}
	if err := model.Delete(ctx, orm.WithWhere("1 = 1")); err != nil {
		return errors.Wrap(err, errors.Database, "清理 scope_visibility_map 失败")
	}
	if len(rows) == 0 {
		return nil
	}
	items := make([]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, row)
	}
	if err := model.Create(ctx, items...); err != nil {
		return errors.Wrap(err, errors.Database, "重建 scope_visibility_map 失败")
	}
	return nil
}

func (r *ScopeRepo) CreateWithConstraint(ctx context.Context, scope *iamentity.Scope, guard iamaccess.WriteConstraint) error {
	return r.Repo.CreateWithConstraint(assocguard.BindContext(ctx, guard), scope, guard.Unwrap())
}

func (r *ScopeRepo) UpdateWithConstraint(ctx context.Context, scope *iamentity.Scope, guard iamaccess.WriteConstraint) error {
	return r.Repo.UpdateWithConstraint(assocguard.BindContext(ctx, guard), scope, guard.Unwrap())
}

func (r *ScopeRepo) DeleteWithConstraint(ctx context.Context, id int64, guard iamaccess.WriteConstraint) error {
	return r.Repo.DeleteWithConstraint(assocguard.BindContext(ctx, guard), id, guard.Unwrap())
}
