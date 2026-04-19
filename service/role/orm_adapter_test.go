package role

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

func newRoleTestOrm(db *gorm.DB) orm.IOrm {
	return &roleTestGormOrm{
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

type roleTestGormOrm struct {
	db           *gorm.DB
	capabilities orm.Capabilities
}

func (g *roleTestGormOrm) Capabilities() orm.Capabilities { return g.capabilities }
func (g *roleTestGormOrm) WithContext(ctx context.Context) orm.IOrm {
	return &roleTestGormOrm{db: g.db.WithContext(ctx), capabilities: g.capabilities}
}
func (g *roleTestGormOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	if meta == nil {
		return nil, errors.NewCode(errors.InvalidInput, "orm model meta cannot be nil")
	}
	return &roleTestGormModel{db: g.db, meta: meta}, nil
}
func (g *roleTestGormOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &roleTestGormSession{roleTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *roleTestGormOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &roleTestGormSession{roleTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *roleTestGormOrm) Database() db.IDatabase { return nil }
func (g *roleTestGormOrm) Raw() any               { return g.db }

type roleTestGormSession struct{ roleTestGormOrm }

func (s *roleTestGormSession) Commit() error   { return s.db.Commit().Error }
func (s *roleTestGormSession) Rollback() error { return s.db.Rollback().Error }

type roleTestGormModel struct {
	db   *gorm.DB
	meta *orm.ModelMeta
}

type roleTestExecResult struct{ rows int64 }

func (r roleTestExecResult) LastInsertId() (int64, error) { return 0, nil }
func (r roleTestExecResult) RowsAffected() (int64, error) { return r.rows, nil }

func (m *roleTestGormModel) Meta() *orm.ModelMeta { return m.meta }
func (m *roleTestGormModel) Capabilities() orm.Capabilities {
	return orm.NewCapabilities(
		orm.CapabilityBasicCRUD,
		orm.CapabilityQuery,
		orm.CapabilityPreload,
		orm.CapabilityAssociationWrite,
		orm.CapabilityBatchWrite,
		orm.CapabilityTransaction,
	)
}

func (m *roleTestGormModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.First(dest).Error; err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Find(dest).Error; err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	db := m.apply(ctx, opts...)
	var count int64
	if err := db.Count(&count).Error; err != nil {
		return 0, convertRoleTestError(err)
	}
	return count, nil
}

func (m *roleTestGormModel) Create(ctx context.Context, entities ...any) error {
	db := m.db.WithContext(ctx)
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return convertRoleTestError(err)
		}
	}
	return nil
}

func (m *roleTestGormModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(entity).Error; err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Updates(values).Error; err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) SaveWithResult(ctx context.Context, entity any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(entity)
	if err := tx.Error; err != nil {
		return nil, convertRoleTestError(err)
	}
	return roleTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *roleTestGormModel) UpdateValuesWithResult(ctx context.Context, values map[string]any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(values)
	if err := tx.Error; err != nil {
		return nil, convertRoleTestError(err)
	}
	return roleTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *roleTestGormModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	db := m.apply(ctx, opts...)
	if err := db.Delete(m.meta.NewModel()).Error; err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) DeleteWithResult(ctx context.Context, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Delete(m.meta.NewModel())
	if err := tx.Error; err != nil {
		return nil, convertRoleTestError(err)
	}
	return roleTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *roleTestGormModel) Association(owner any, name string) orm.IAssociation {
	return &roleTestGormAssociation{db: m.db, owner: owner, name: name}
}

type roleTestGormAssociation struct {
	db    *gorm.DB
	owner any
	name  string
}

func (a *roleTestGormAssociation) Name() string { return a.name }
func (a *roleTestGormAssociation) Owner() any   { return a.owner }

func (a *roleTestGormAssociation) Append(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Append(targets...); err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (a *roleTestGormAssociation) Replace(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Replace(targets...); err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (a *roleTestGormAssociation) Delete(ctx context.Context, targets ...any) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Delete(targets...); err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (a *roleTestGormAssociation) Clear(ctx context.Context) error {
	if err := a.db.WithContext(ctx).Model(a.owner).Association(a.name).Clear(); err != nil {
		return convertRoleTestError(err)
	}
	return nil
}

func (m *roleTestGormModel) apply(ctx context.Context, opts ...orm.QueryOption) *gorm.DB {
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
		db = db.Joins(buildRoleTestJoinExpr(join))
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

func buildRoleTestJoinExpr(j orm.Join) string {
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

func convertRoleTestError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.NewCode(errors.NotFound, "record not found")
	}
	return err
}
