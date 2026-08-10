package menu

import (
	"context"
	"database/sql"

	"gochen/db"
	"gochen/db/dialect"
	"gochen/db/orm"
	"gochen/errors"

	"gorm.io/gorm"
)

type menuTestExecResult struct{ rows int64 }

func (r menuTestExecResult) LastInsertId() (int64, error) { return 0, nil }
func (r menuTestExecResult) RowsAffected() (int64, error) { return r.rows, nil }

func newMenuTestOrm(db *gorm.DB) orm.IOrm {
	return &menuTestGormOrm{
		db: db,
		capabilities: orm.NewCapabilities(
			orm.CapabilityBasicCRUD,
			orm.CapabilityQuery,
			orm.CapabilityTransaction,
		),
	}
}

type menuTestGormOrm struct {
	db           *gorm.DB
	capabilities orm.Capabilities
}

func (g *menuTestGormOrm) Capabilities() orm.Capabilities { return g.capabilities }
func (g *menuTestGormOrm) WithContext(ctx context.Context) orm.IOrm {
	return &menuTestGormOrm{db: g.db.WithContext(ctx), capabilities: g.capabilities}
}
func (g *menuTestGormOrm) Model(meta *orm.ModelMeta) (orm.IModel, error) {
	if meta == nil {
		return nil, errors.NewCode(errors.InvalidInput, "orm model meta cannot be nil")
	}
	return &menuTestGormModel{db: g.db, meta: meta}, nil
}
func (g *menuTestGormOrm) Begin(ctx context.Context) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &menuTestGormSession{menuTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *menuTestGormOrm) BeginTx(ctx context.Context, opts *sql.TxOptions) (orm.IOrmSession, error) {
	tx := g.db.WithContext(ctx).Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &menuTestGormSession{menuTestGormOrm{db: tx, capabilities: g.capabilities}}, nil
}
func (g *menuTestGormOrm) Database() db.IDatabase { return nil }
func (g *menuTestGormOrm) Raw() any               { return g.db }

type menuTestGormSession struct{ menuTestGormOrm }

func (s *menuTestGormSession) Commit() error   { return s.db.Commit().Error }
func (s *menuTestGormSession) Rollback() error { return s.db.Rollback().Error }

type menuTestGormModel struct {
	db   *gorm.DB
	meta *orm.ModelMeta
}

func (m *menuTestGormModel) Meta() *orm.ModelMeta { return m.meta }
func (m *menuTestGormModel) Capabilities() orm.Capabilities {
	return orm.NewCapabilities(
		orm.CapabilityBasicCRUD,
		orm.CapabilityQuery,
		orm.CapabilityTransaction,
	)
}

func (m *menuTestGormModel) Dialect() dialect.IDialect {
	return dialect.New(m.db.Dialector.Name())
}

func (m *menuTestGormModel) First(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	if err := m.apply(ctx, opts...).First(dest).Error; err != nil {
		return convertMenuTestError(err)
	}
	return nil
}

func (m *menuTestGormModel) Find(ctx context.Context, dest any, opts ...orm.QueryOption) error {
	if err := m.apply(ctx, opts...).Find(dest).Error; err != nil {
		return convertMenuTestError(err)
	}
	return nil
}

func (m *menuTestGormModel) Count(ctx context.Context, opts ...orm.QueryOption) (int64, error) {
	var count int64
	if err := m.apply(ctx, opts...).Count(&count).Error; err != nil {
		return 0, convertMenuTestError(err)
	}
	return count, nil
}

func (m *menuTestGormModel) Create(ctx context.Context, entities ...any) error {
	db := m.db.WithContext(ctx)
	for _, entity := range entities {
		if err := db.Create(entity).Error; err != nil {
			return convertMenuTestError(err)
		}
	}
	return nil
}

func (m *menuTestGormModel) Save(ctx context.Context, entity any, opts ...orm.QueryOption) error {
	if err := m.apply(ctx, opts...).Updates(entity).Error; err != nil {
		return convertMenuTestError(err)
	}
	return nil
}

func (m *menuTestGormModel) UpdateValues(ctx context.Context, values map[string]any, opts ...orm.QueryOption) error {
	if err := m.apply(ctx, opts...).Updates(values).Error; err != nil {
		return convertMenuTestError(err)
	}
	return nil
}

func (m *menuTestGormModel) SaveWithResult(ctx context.Context, entity any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(entity)
	if err := tx.Error; err != nil {
		return nil, convertMenuTestError(err)
	}
	return menuTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *menuTestGormModel) UpdateValuesWithResult(ctx context.Context, values map[string]any, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Updates(values)
	if err := tx.Error; err != nil {
		return nil, convertMenuTestError(err)
	}
	return menuTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *menuTestGormModel) Delete(ctx context.Context, opts ...orm.QueryOption) error {
	if err := m.apply(ctx, opts...).Delete(m.meta.NewModel()).Error; err != nil {
		return convertMenuTestError(err)
	}
	return nil
}

func (m *menuTestGormModel) DeleteWithResult(ctx context.Context, opts ...orm.QueryOption) (sql.Result, error) {
	db := m.apply(ctx, opts...)
	tx := db.Delete(m.meta.NewModel())
	if err := tx.Error; err != nil {
		return nil, convertMenuTestError(err)
	}
	return menuTestExecResult{rows: tx.RowsAffected}, nil
}

func (m *menuTestGormModel) Association(owner any, name string) orm.IAssociation { return nil }

func (m *menuTestGormModel) apply(ctx context.Context, opts ...orm.QueryOption) *gorm.DB {
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
	if qo.Limit > 0 {
		db = db.Limit(qo.Limit)
	}
	if qo.Offset > 0 {
		db = db.Offset(qo.Offset)
	}
	return db
}

func convertMenuTestError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.NewCode(errors.NotFound, "record not found")
	}
	return err
}
