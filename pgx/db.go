package pgx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const defaultPingTimeout = 5 * time.Second

// uniqueViolationCode is the PostgreSQL SQLSTATE for a unique constraint
// violation.
const uniqueViolationCode = "23505"

// DBConfig describes a PostgreSQL connection pool. Driver is typically "pgx"
// (register github.com/jackc/pgx/v5/stdlib via a blank import). A non-positive
// MaxOpenConns or MaxIdleConns leaves the database/sql default in place;
// PingTimeout defaults to five seconds.
type DBConfig struct {
	Driver          string
	Source          string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	PingTimeout     time.Duration
}

// OpenDB opens a connection pool from cfg, applies the pool settings, and
// verifies connectivity with a bounded ping. It returns the pool and a cleanup
// that closes it; logger may be nil. On any failure the pool is closed and the
// error is returned.
func OpenDB(ctx context.Context, cfg DBConfig, logger *slog.Logger) (*sql.DB, func(), error) {
	if logger == nil {
		logger = slog.Default()
	}

	db, err := sql.Open(cfg.Driver, cfg.Source)
	if err != nil {
		return nil, nil, fmt.Errorf("open db: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	logger.InfoContext(ctx, "database pool configured",
		"max_open_conns", cfg.MaxOpenConns,
		"max_idle_conns", cfg.MaxIdleConns,
		"conn_max_lifetime", cfg.ConnMaxLifetime,
	)

	pingTimeout := cfg.PingTimeout
	if pingTimeout <= 0 {
		pingTimeout = defaultPingTimeout
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("ping db: %w", err)
	}

	cleanup := func() {
		if err := db.Close(); err != nil {
			logger.ErrorContext(context.WithoutCancel(ctx), "failed to close database", "err", err)
		}
	}
	return db, cleanup, nil
}

// IsUniqueViolation reports whether err is a PostgreSQL unique constraint
// violation (SQLSTATE 23505), unwrapping through the error chain.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode
}

// rollbacker is satisfied by *sql.Tx; it is accepted as an interface so the
// rollback bookkeeping can be tested without a live transaction.
type rollbacker interface {
	Rollback() error
}

// RollbackOnError rolls back tx when *errp is non-nil, joining any rollback
// failure into *errp. It is meant to be deferred:
//
//	defer pgx.RollbackOnError(tx, &err)
//
// A failed Commit already finalizes the transaction, so the deferred rollback
// then returns sql.ErrTxDone; that is treated as noise and not joined.
func RollbackOnError(tx rollbacker, errp *error) {
	if errp == nil || *errp == nil {
		return
	}
	if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		*errp = errors.Join(*errp, fmt.Errorf("rollback: %w", rollbackErr))
	}
}
