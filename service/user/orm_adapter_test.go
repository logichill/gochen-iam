package user_test

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

// newTestOrm 为用户集成测试提供最小 GORM 适配器。
func newTestOrm(db *gorm.DB) orm.IOrm {
	return &testGormOrm{
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

type testGormOrm struct {
	db           *gorm.DB
	capabilities orm.Capabilities
}

func (g *testGormOrm) Capabilities() orm.Capabilities { return g.capabilities }
func (g *testGormOrm) WithContext(ctx context.Context) orm.IOrm {
	return &testGormOrm{db: g.db.WithContext(ctx), capabilities: g.capabilities}
}
func (g *testGormOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	if meta == nil {
		return nil, errorx.New(errorx.InvalidInput, "orm model meta cannot be nil")
	}
	return &testGormModel{db: g.db, meta: meta}, nil
}
func (g *testGormOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &testGormSession{testGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *testGormOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &testGormSession{testGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *testGormOrm) Database() database.IDatabase { return nil }
func (g *testGormOrm) Raw() any                     { return g.db }

type testGormSession struct{ testGormOrm }

func (s *testGormSession) Commit() error   { return s.db.Commit().Error }
func (s *testGormSession) Rollback() error { return s.db.Rollback().Error }

type testGormModel struct {
	db   *gorm.DB
	meta *orm.ModelMeta
}

func (m *testGormModel) Meta() *orm.ModelMeta { return m.meta }
func (m *testGormModel) Capabilities() orm.Capabilities {
	return orm.NewCapabilities(
		orm.CapabilityBasicCRUD,
		orm.CapabilityQuery,
		orm.CapabilityPreload,
		orm.CapabilityAssociationWrite,
		orm.CapabilityBatchWrite,
		orm.CapabilityTransaction,
	)
}

func (m *testGormModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.First(dest).Error; err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Find(dest).Error; err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	db := m.apply(ctx, opts...)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, convertTestError(err)
	}
	return count, nil
}

func (m *testGormModel) Create(ctx context.Context, entities ...any) error {
	db := m.db.WithContext(ctx)
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return convertTestError(err)
		}
	}
	return nil
}

func (m *testGormModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(entity).Error; err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(values).Error; err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Delete(m.meta.NewModel()).Error; err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) Association(owner any, name string) orm.IAssociation {
	return &testGormAssociation{db: m.db, owner: owner, name: name}
}

type testGormAssociation struct {
	db    *gorm.DB
	owner any
	name  string
}

func (a *testGormAssociation) Name() string { return a.name }
func (a *testGormAssociation) Owner() any   { return a.owner }

func (a *testGormAssociation) Append(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Append(targets...); err != nil {
		return convertTestError(err)
	}
	return nil
}

func (a *testGormAssociation) Replace(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Replace(targets...); err != nil {
		return convertTestError(err)
	}
	return nil
}

func (a *testGormAssociation) Delete(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Delete(targets...); err != nil {
		return convertTestError(err)
	}
	return nil
}

func (a *testGormAssociation) Clear(ctx context.Context) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Clear(); err != nil {
		return convertTestError(err)
	}
	return nil
}

func (m *testGormModel) apply(ctx context.Context, opts ...orm.QueryOption) *gorm.DB {
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

func convertTestError(err error) error {
	if ers.Is(err, gorm.ErrRecordNotFound) {
		return errorx.New(errorx.NotFound, "record not found")
	}
	return err
}
