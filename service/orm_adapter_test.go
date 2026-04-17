package service

import (
	"context"
	"database/sql"
	ers "errors"
	"fmt"
	"strings"

	database "gochen/db"
	"gochen/db/orm"
	"gochen/errorx"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func newScopeAuthorizerTestOrm(db *gorm.DB) orm.IOrm {
	return &scopeAuthorizerTestOrm{
		db: db,
		capabilities: orm.NewCapabilities(
			orm.CapabilityBasicCRUD,
			orm.CapabilityQuery,
			orm.CapabilityPreload,
			orm.CapabilityAssociationWrite,
			orm.CapabilityBatchWrite,
			orm.CapabilityTransaction,
		),
	}
}

type scopeAuthorizerTestOrm struct {
	db           *gorm.DB
	capabilities orm.Capabilities
}

func (g *scopeAuthorizerTestOrm) Capabilities() orm.Capabilities { return g.capabilities }
func (g *scopeAuthorizerTestOrm) WithContext(ctx context.Context) orm.IOrm {
	return &scopeAuthorizerTestOrm{db: g.db.WithContext(ctx), capabilities: g.capabilities}
}
func (g *scopeAuthorizerTestOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	if meta == nil {
		return nil, errorx.New(errorx.InvalidInput, "orm model meta cannot be nil")
	}
	return &scopeAuthorizerTestModel{db: g.db, meta: meta}, nil
}
func (g *scopeAuthorizerTestOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &scopeAuthorizerTestSession{scopeAuthorizerTestOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *scopeAuthorizerTestOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &scopeAuthorizerTestSession{scopeAuthorizerTestOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *scopeAuthorizerTestOrm) Database() database.IDatabase { return nil }
func (g *scopeAuthorizerTestOrm) Raw() any                     { return g.db }

type scopeAuthorizerTestSession struct{ scopeAuthorizerTestOrm }

func (s *scopeAuthorizerTestSession) Commit() error   { return s.db.Commit().Error }
func (s *scopeAuthorizerTestSession) Rollback() error { return s.db.Rollback().Error }

type scopeAuthorizerTestModel struct {
	db   *gorm.DB
	meta *orm.ModelMeta
}

type scopeAuthorizerTestExecResult struct{ rows int64 }

func (r scopeAuthorizerTestExecResult) LastInsertId() (int64, error) { return 0, nil }
func (r scopeAuthorizerTestExecResult) RowsAffected() (int64, error) { return r.rows, nil }

func (m *scopeAuthorizerTestModel) Meta() *orm.ModelMeta { return m.meta }
func (m *scopeAuthorizerTestModel) Capabilities() orm.Capabilities {
	return orm.NewCapabilities(
		orm.CapabilityBasicCRUD,
		orm.CapabilityQuery,
		orm.CapabilityPreload,
		orm.CapabilityAssociationWrite,
		orm.CapabilityBatchWrite,
		orm.CapabilityTransaction,
	)
}

func (m *scopeAuthorizerTestModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.First(dest).Error; err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Find(dest).Error; err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	db := m.apply(ctx, opts...)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, convertScopeAuthorizerTestError(err)
	}
	return count, nil
}

func (m *scopeAuthorizerTestModel) Create(ctx context.Context, entities ...any) error {
	db := m.db.WithContext(ctx)
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return convertScopeAuthorizerTestError(err)
		}
	}
	return nil
}

func (m *scopeAuthorizerTestModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(entity).Error; err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(values).Error; err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) SaveWithResult(ctx context.Context, entity any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(entity)
	if err := tx.Error; err != nil {
		return nil, convertScopeAuthorizerTestError(err)
	}
	return scopeAuthorizerTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeAuthorizerTestModel) UpdateValuesWithResult(ctx context.Context, values map[string]any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(values)
	if err := tx.Error; err != nil {
		return nil, convertScopeAuthorizerTestError(err)
	}
	return scopeAuthorizerTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeAuthorizerTestModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Delete(m.meta.NewModel()).Error; err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) DeleteWithResult(ctx context.Context, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Delete(m.meta.NewModel())
	if err := tx.Error; err != nil {
		return nil, convertScopeAuthorizerTestError(err)
	}
	return scopeAuthorizerTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *scopeAuthorizerTestModel) Association(owner any, name string) orm.IAssociation {
	return &scopeAuthorizerTestAssociation{db: m.db, owner: owner, name: name}
}

type scopeAuthorizerTestAssociation struct {
	db    *gorm.DB
	owner any
	name  string
}

func (a *scopeAuthorizerTestAssociation) Name() string { return a.name }
func (a *scopeAuthorizerTestAssociation) Owner() any   { return a.owner }

func (a *scopeAuthorizerTestAssociation) Append(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Append(targets...); err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (a *scopeAuthorizerTestAssociation) Replace(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Replace(targets...); err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (a *scopeAuthorizerTestAssociation) Delete(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Delete(targets...); err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (a *scopeAuthorizerTestAssociation) Clear(ctx context.Context) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Clear(); err != nil {
		return convertScopeAuthorizerTestError(err)
	}
	return nil
}

func (m *scopeAuthorizerTestModel) apply(ctx context.Context, opts ...orm.QueryOption) *gorm.DB {
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
		db = db.Joins(buildScopeAuthorizerJoinExpr(join))
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

func buildScopeAuthorizerJoinExpr(j orm.Join) string {
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

func convertScopeAuthorizerTestError(err error) error {
	if err == nil {
		return nil
	}
	if ers.Is(err, gorm.ErrRecordNotFound) {
		return errorx.New(errorx.NotFound, "record not found")
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unique"):
		return errorx.Wrap(err, errorx.Conflict, "unique constraint violation")
	case strings.Contains(msg, "foreign key"):
		return errorx.Wrap(err, errorx.Validation, "foreign key constraint violation")
	default:
		return errorx.Wrap(err, errorx.Database, fmt.Sprintf("database error: %v", err))
	}
}
