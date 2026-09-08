package middleware

import (
	"context"
	"database/sql"
	stderrors "errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"gochen-runtime/db/sql/stdsql"
	"gochen/db"
)

func TestEnsureDatabaseRevokedTokenSchemaIncludesExpiryIndexForMySQL(t *testing.T) {
	database := &revokedTokenSchemaCaptureDatabase{dialect: "mysql"}
	if err := EnsureDatabaseRevokedTokenSchema(t.Context(), database); err != nil {
		t.Fatalf("EnsureDatabaseRevokedTokenSchema: %v", err)
	}
	if len(database.queries) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(database.queries))
	}
	if !strings.Contains(database.queries[0], "INDEX idx_iam_revoked_tokens_expires_at") {
		t.Fatalf("MySQL DDL does not include expiry index: %s", database.queries[0])
	}
}

func TestDatabaseRevokedTokenStorePersistsAcrossInstancesAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.db")
	database := openRevokedTokenTestDatabase(t, path)
	store1, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore: %v", err)
	}
	consumed, err := store1.Consume(t.Context(), "shared-jti", time.Now().Add(time.Hour))
	if err != nil || !consumed {
		t.Fatalf("first Consume = %v, %v; want true, nil", consumed, err)
	}
	store2, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore second instance: %v", err)
	}
	if revoked, err := store2.IsRevoked(t.Context(), "shared-jti"); err != nil || !revoked {
		t.Fatalf("second store IsRevoked = %v, %v; want true, nil", revoked, err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	reopened := openRevokedTokenTestDatabase(t, path)
	store3, err := NewDatabaseRevokedTokenStore(reopened)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore after reopen: %v", err)
	}
	if revoked, err := store3.IsRevoked(t.Context(), "shared-jti"); err != nil || !revoked {
		t.Fatalf("reopened store IsRevoked = %v, %v; want true, nil", revoked, err)
	}
}

func TestDatabaseRevokedTokenStoreConsumeIsAtomic(t *testing.T) {
	database := openRevokedTokenTestDatabase(t, filepath.Join(t.TempDir(), "concurrent.db"))
	store1, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore: %v", err)
	}
	store2, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore second instance: %v", err)
	}
	stores := []*DatabaseRevokedTokenStore{store1, store2}

	const workers = 32
	start := make(chan struct{})
	var successes atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(store *DatabaseRevokedTokenStore) {
			defer wg.Done()
			<-start
			consumed, err := store.Consume(t.Context(), "concurrent-jti", time.Now().Add(time.Hour))
			if err != nil {
				errs <- err
				return
			}
			if consumed {
				successes.Add(1)
			}
		}(stores[i%len(stores)])
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Consume: %v", err)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful consumes = %d, want 1", got)
	}
}

func TestDatabaseRevokedTokenStoreIgnoresExpiredRecords(t *testing.T) {
	database := openRevokedTokenTestDatabase(t, filepath.Join(t.TempDir(), "expired.db"))
	if _, err := database.Exec(t.Context(),
		"INSERT INTO iam_revoked_tokens (jti, expires_at) VALUES (?, ?)",
		"expired-jti",
		time.Now().Add(-revokedTokenClockSkew-time.Minute).Unix(),
	); err != nil {
		t.Fatalf("insert expired record: %v", err)
	}
	store, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore: %v", err)
	}
	if revoked, err := store.IsRevoked(t.Context(), "expired-jti"); err != nil || revoked {
		t.Fatalf("IsRevoked expired = %v, %v; want false, nil", revoked, err)
	}
	if consumed, err := store.Consume(t.Context(), "expired-jti", time.Now().Add(time.Hour)); err != nil || !consumed {
		t.Fatalf("Consume after expiry = %v, %v; want true, nil", consumed, err)
	}
}

func TestDatabaseRevokedTokenStoreRetainsExpiredRecordDuringClockSkewGrace(t *testing.T) {
	database := openRevokedTokenTestDatabase(t, filepath.Join(t.TempDir(), "clock-skew.db"))
	if _, err := database.Exec(t.Context(),
		"INSERT INTO iam_revoked_tokens (jti, expires_at) VALUES (?, ?)",
		"clock-skew-jti",
		time.Now().Add(-time.Minute).Unix(),
	); err != nil {
		t.Fatalf("insert clock-skew record: %v", err)
	}
	store, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore: %v", err)
	}
	if revoked, err := store.IsRevoked(t.Context(), "clock-skew-jti"); err != nil || !revoked {
		t.Fatalf("IsRevoked during grace = %v, %v; want true, nil", revoked, err)
	}
	if consumed, err := store.Consume(t.Context(), "clock-skew-jti", time.Now().Add(time.Hour)); err != nil || consumed {
		t.Fatalf("Consume during grace = %v, %v; want false, nil", consumed, err)
	}
}

func TestDatabaseRevokedTokenStorePropagatesCanceledContext(t *testing.T) {
	database := openRevokedTokenTestDatabase(t, filepath.Join(t.TempDir(), "canceled.db"))
	store, err := NewDatabaseRevokedTokenStore(database)
	if err != nil {
		t.Fatalf("NewDatabaseRevokedTokenStore: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Consume(ctx, "canceled-consume", time.Now().Add(time.Hour)); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("Consume error = %v, want context.Canceled", err)
	}
	if _, err := store.IsRevoked(ctx, "canceled-query"); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("IsRevoked error = %v, want context.Canceled", err)
	}
}

func openRevokedTokenTestDatabase(t *testing.T, path string) db.IDatabase {
	t.Helper()
	database, err := stdsql.New(db.DBConfig{
		Driver:       "sqlite3",
		Database:     path,
		MaxOpenConns: 1,
		MaxIdleConns: 1,
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := EnsureDatabaseRevokedTokenSchema(t.Context(), database); err != nil {
		t.Fatalf("EnsureDatabaseRevokedTokenSchema: %v", err)
	}
	return database
}

type revokedTokenSchemaCaptureDatabase struct {
	db.IDatabase
	dialect string
	queries []string
}

func (d *revokedTokenSchemaCaptureDatabase) DialectName() string { return d.dialect }

func (d *revokedTokenSchemaCaptureDatabase) Exec(_ context.Context, query string, _ ...any) (sql.Result, error) {
	d.queries = append(d.queries, query)
	return revokedTokenSchemaResult(0), nil
}

type revokedTokenSchemaResult int64

func (r revokedTokenSchemaResult) LastInsertId() (int64, error) { return int64(r), nil }
func (r revokedTokenSchemaResult) RowsAffected() (int64, error) { return int64(r), nil }
