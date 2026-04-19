package scope

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"gochen/db"
	"gochen/db/orm"
	"gochen/errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func newScopeTestOrm(db *gorm.DB) orm.IOrm {
	return &scopeTestGormOrm{
		db: db,
		capabilities: orm.NewCapabilities(
			orm.CapabilityBasicCRUD,
			orm.CapabilityQuery,
			orm.CapabilityBatchWrite,
			orm.CapabilityTransaction,
		),
	}
}

type scopeTestGormOrm struct {
	db           *gorm.DB
	capabilities orm.Capabilities
}

func (g *scopeTestGormOrm) Capabilities() orm.Capabilities { return g.capabilities }
func (g *scopeTestGormOrm) WithContext(ctx context.Context) orm.IOrm {
	return &scopeTestGormOrm{db: g.db.WithContext(ctx), capabilities: g.capabilities}
}
func (g *scopeTestGormOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	if meta == nil {
		return nil, errors.NewCode(errors.InvalidInput, "orm model meta cannot be nil")
	}
	return &scopeTestGormModel{db: g.db, meta: meta}, nil
}
func (g *scopeTestGormOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &scopeTestGormSession{scopeTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *scopeTestGormOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &scopeTestGormSession{scopeTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *scopeTestGormOrm) Database() db.IDatabase { return nil }
func (g *scopeTestGormOrm) Raw() any               { return g.db }

type scopeTestGormSession struct{ scopeTestGormOrm }

func (s *scopeTestGormSession) Commit() error   { return s.db.Commit().Error }
func (s *scopeTestGormSession) Rollback() error { return s.db.Rollback().Error }

type scopeTestGormModel struct {
	db   *gorm.DB
	meta *orm.ModelMeta
}

type scopeTestExecResult struct{ rows int64 }

func (r scopeTestExecResult) LastInsertId() (int64, error) { return 0, nil }
func (r scopeTestExecResult) RowsAffected() (int64, error) { return r.rows, nil }

func (m *scopeTestGormModel) Meta() *orm.ModelMeta { return m.meta }
func (m *scopeTestGormModel) Capabilities() orm.Capabilities {
	return orm.NewCapabilities(
		orm.CapabilityBasicCRUD,
		orm.CapabilityQuery,
		orm.CapabilityBatchWrite,
		orm.CapabilityTransaction,
	)
}

func (m *scopeTestGormModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.First(dest).Error; err != nil {
		return convertScopeTestError(err)
	}
	return nil
}

func (m *scopeTestGormModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Find(dest).Error; err != nil {
		return convertScopeTestError(err)
	}
	return nil
}

func (m *scopeTestGormModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	db := m.apply(ctx, opts...)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, convertScopeTestError(err)
	}
	return count, nil
}

func (m *scopeTestGormModel) Create(ctx context.Context, entities ...any) error {
	db := m.db.WithContext(ctx)
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return convertScopeTestError(err)
		}
	}
	return nil
}

func (m *scopeTestGormModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(entity).Error; err != nil {
		return convertScopeTestError(err)
	}
	return nil
}

func (m *scopeTestGormModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(values).Error; err != nil {
		return convertScopeTestError(err)
	}
	return nil
}

func (m *scopeTestGormModel) SaveWithResult(ctx context.Context, entity any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(entity)
	if err := tx.Error; err != nil {
		return nil, convertScopeTestError(err)
	}
	return scopeTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeTestGormModel) UpdateValuesWithResult(ctx context.Context, values map[string]any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(values)
	if err := tx.Error; err != nil {
		return nil, convertScopeTestError(err)
	}
	return scopeTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeTestGormModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Delete(m.meta.NewModel()).Error; err != nil {
		return convertScopeTestError(err)
	}
	return nil
}

func (m *scopeTestGormModel) DeleteWithResult(ctx context.Context, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Delete(m.meta.NewModel())
	if err := tx.Error; err != nil {
		return nil, convertScopeTestError(err)
	}
	return scopeTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeTestGormModel) Association(any, string) orm.IAssociation { return nil }

func (m *scopeTestGormModel) apply(ctx context.Context, opts ...orm.QueryOption) *gorm.DB {
	db := m.db.WithContext(ctx)
	if m.meta != nil {
		if m.meta.Table != "" {
			db = db.Table(m.meta.Table)
		} else if model := m.meta.NewModel(); model != nil {
			db = db.Model(model)
		}
	}
	qo := orm.CollectQueryOptions(opts...)
	for _, cond := range qo.Where {
		db = db.Where(cond.Expr, cond.Args...)
	}
	for _, join := range qo.Joins {
		db = db.Joins(buildJoinExpr(join))
	}
	for _, preload := range qo.Preload {
		db = db.Preload(preload)
	}
	for _, order := range qo.OrderBy {
		dir := "ASC"
		if order.Desc {
			dir = "DESC"
		}
		db = db.Order(order.Column + " " + dir)
	}
	if len(qo.Select) > 0 {
		db = db.Select(qo.Select)
	}
	for _, group := range qo.GroupBy {
		db = db.Group(group)
	}
	if qo.Limit > 0 {
		db = db.Limit(qo.Limit)
	}
	if qo.Offset > 0 {
		db = db.Offset(qo.Offset)
	}
	if qo.ForUpdate {
		db = db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return db
}

func buildJoinExpr(j orm.Join) string {
	joinType := strings.TrimSpace(string(j.Type))
	if joinType == "" {
		joinType = string(orm.JoinInner)
	}
	target := j.Table
	if strings.TrimSpace(j.Alias) != "" {
		target = fmt.Sprintf("%s AS %s", j.Table, j.Alias)
	}
	expr := fmt.Sprintf("%s JOIN %s", joinType, target)
	if len(j.On) > 0 {
		expr += fmt.Sprintf(" ON %s = %s", j.On[0].Left, j.On[0].Right)
		for i := 1; i < len(j.On); i++ {
			expr += fmt.Sprintf(" AND %s = %s", j.On[i].Left, j.On[i].Right)
		}
	}
	return expr
}

func convertScopeTestError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.NewCode(errors.NotFound, "record not found")
	}
	return err
}
