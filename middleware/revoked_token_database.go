package middleware

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	coredialect "gochen/db/dialect"
	"strings"
	"time"

	"gochen-runtime/db/dialect"
	"gochen/db"
	"gochen/errors"
)

const (
	revokedTokenTable            = "iam_revoked_tokens"
	revokedTokenCleanupBatchSize = 5000
)

// DatabaseRevokedTokenStore 使用应用主数据库共享 access token 吊销状态。
type DatabaseRevokedTokenStore struct {
	database db.IDatabase
}

// NewDatabaseRevokedTokenStore 创建数据库吊销存储。表结构必须由应用迁移预先创建。
func NewDatabaseRevokedTokenStore(database db.IDatabase) (*DatabaseRevokedTokenStore, error) {
	if database == nil {
		return nil, errors.NewCode(errors.InvalidInput, "database is nil")
	}
	return &DatabaseRevokedTokenStore{database: database}, nil
}

// EnsureDatabaseRevokedTokenSchema 为没有正式主库迁移链的应用创建最小表结构。
func EnsureDatabaseRevokedTokenSchema(ctx context.Context, database db.IDatabase) error {
	if database == nil {
		return errors.NewCode(errors.InvalidInput, "database is nil")
	}
	if ctx == nil {
		return errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	dialectName := dialect.FromDatabase(database).Name()
	ddl := `CREATE TABLE IF NOT EXISTS iam_revoked_tokens (
  jti VARCHAR(191) PRIMARY KEY,
  expires_at BIGINT NOT NULL
)`
	if dialectName == coredialect.NameMySQL {
		ddl = `CREATE TABLE IF NOT EXISTS iam_revoked_tokens (
  jti VARCHAR(191) PRIMARY KEY,
  expires_at BIGINT NOT NULL,
  INDEX idx_iam_revoked_tokens_expires_at (expires_at)
)`
	}
	if _, err := database.Exec(ctx, ddl); err != nil {
		return errors.Wrap(err, errors.Internal, "初始化 token 吊销表失败")
	}
	if dialectName != coredialect.NameMySQL {
		const indexDDL = `CREATE INDEX IF NOT EXISTS idx_iam_revoked_tokens_expires_at
ON iam_revoked_tokens (expires_at)`
		if _, err := database.Exec(ctx, indexDDL); err != nil {
			return errors.Wrap(err, errors.Internal, "初始化 token 吊销表索引失败")
		}
	}
	return nil
}

func (s *DatabaseRevokedTokenStore) Consume(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if ctx == nil {
		return false, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	jti = strings.TrimSpace(jti)
	if jti == "" || expiresAt.IsZero() {
		return false, errors.NewCode(errors.InvalidInput, "token JTI 与过期时间不能为空")
	}
	if s == nil || s.database == nil {
		return false, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储不可用")
	}

	_, err := s.database.Exec(ctx,
		"INSERT INTO "+revokedTokenTable+" (jti, expires_at) VALUES (?, ?)",
		jti,
		expiresAt.Unix(),
	)
	if err == nil {
		return true, nil
	}
	if db.IsUniqueViolation(err) {
		cleanupBeforeUnix := time.Now().Add(-revokedTokenClockSkew).Unix()
		res, delErr := s.database.Exec(ctx,
			"DELETE FROM "+revokedTokenTable+" WHERE jti = ? AND expires_at <= ?",
			jti,
			cleanupBeforeUnix,
		)
		if delErr == nil && res != nil {
			if n, _ := res.RowsAffected(); n > 0 {
				_, retryErr := s.database.Exec(ctx,
					"INSERT INTO "+revokedTokenTable+" (jti, expires_at) VALUES (?, ?)",
					jti,
					expiresAt.Unix(),
				)
				if retryErr == nil {
					return true, nil
				}
			}
		}
		return false, nil
	}
	return false, errors.Wrap(err, errors.ServiceUnavailable, "写入 token 吊销记录失败")
}

// CleanupExpired 清理已过期的 token 吊销记录，供后台定时清理任务调用，分批 LIMIT 避免长事务与大范围行级锁争用。
func (s *DatabaseRevokedTokenStore) CleanupExpired(ctx context.Context) (int64, error) {
	if ctx == nil {
		return 0, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	if s == nil || s.database == nil {
		return 0, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储不可用")
	}
	cleanupBeforeUnix := time.Now().Add(-revokedTokenClockSkew).Unix()
	var totalDeleted int64
	for {
		if ctx.Err() != nil {
			return totalDeleted, ctx.Err()
		}
		query := fmt.Sprintf(
			"DELETE FROM %s WHERE jti IN (SELECT jti FROM (SELECT jti FROM %s WHERE expires_at <= ? LIMIT %d) AS expired_batch)",
			revokedTokenTable, revokedTokenTable, revokedTokenCleanupBatchSize,
		)
		res, err := s.database.Exec(ctx, query, cleanupBeforeUnix)
		if err != nil {
			if totalDeleted == 0 {
				fallbackRes, fallbackErr := s.database.Exec(ctx, "DELETE FROM "+revokedTokenTable+" WHERE expires_at <= ?", cleanupBeforeUnix)
				if fallbackErr != nil {
					return 0, errors.Wrap(fallbackErr, errors.ServiceUnavailable, "清理过期 token 吊销记录失败")
				}
				if fallbackRes != nil {
					return fallbackRes.RowsAffected()
				}
				return 0, nil
			}
			return totalDeleted, errors.Wrap(err, errors.ServiceUnavailable, "清理过期 token 吊销记录失败")
		}
		if res == nil {
			break
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return totalDeleted, errors.Wrap(err, errors.ServiceUnavailable, "读取清理过期记录影响行数失败")
		}
		totalDeleted += affected
		if affected < revokedTokenCleanupBatchSize {
			break
		}
	}
	return totalDeleted, nil
}

func (s *DatabaseRevokedTokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if ctx == nil {
		return false, errors.NewCode(errors.InvalidInput, "ctx is nil")
	}
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false, nil
	}
	if s == nil || s.database == nil {
		return false, errors.NewCode(errors.ServiceUnavailable, "token 吊销存储不可用")
	}

	var expiresAtUnix int64
	err := s.database.QueryRow(ctx,
		"SELECT expires_at FROM "+revokedTokenTable+" WHERE jti = ?",
		jti,
	).Scan(&expiresAtUnix)
	if stderrors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.Wrap(err, errors.ServiceUnavailable, "查询 token 吊销状态失败")
	}
	cleanupBeforeUnix := time.Now().Add(-revokedTokenClockSkew).Unix()
	if expiresAtUnix <= cleanupBeforeUnix {
		_, _ = s.database.Exec(ctx,
			"DELETE FROM "+revokedTokenTable+" WHERE jti = ? AND expires_at <= ?",
			jti,
			cleanupBeforeUnix,
		)
		return false, nil
	}
	return true, nil
}
