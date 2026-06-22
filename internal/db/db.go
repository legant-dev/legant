package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/config"
)

func NewPool(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing database URL: %w", err)
	}

	poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.MaxIdleConns)

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}

// WithTx runs fn inside a database transaction, committing on success and rolling
// back on any error or panic. Security-critical writes (e.g. minting an exchanged
// token together with its audit record) use this so the two either both commit or
// neither does.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is a no-op once the tx has committed, so this is safe to always defer.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func newMigrator(migrationsFS fs.FS, databaseURL string) (*migrate.Migrate, error) {
	source, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("creating migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating migrator: %w", err)
	}
	return m, nil
}

// RunMigrations applies all pending migrations. It refuses to proceed if the
// schema_migrations table is marked dirty (a prior migration failed mid-way),
// which must be resolved by an operator rather than silently retried.
func RunMigrations(migrationsFS fs.FS, databaseURL string) error {
	m, err := newMigrator(migrationsFS, databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()

	if v, dirty, err := m.Version(); err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("reading migration version: %w", err)
	} else if dirty {
		return fmt.Errorf("database is dirty at migration version %d; resolve manually before migrating", v)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	version, dirty, _ := m.Version()
	slog.Info("migrations complete", "version", version, "dirty", dirty)
	return nil
}

// MigrateDownAll rolls back every applied migration. It is destructive and used
// only by the migration round-trip test and the guarded `legant migrate down`
// command — never in normal operation.
func MigrateDownAll(migrationsFS fs.FS, databaseURL string) error {
	m, err := newMigrator(migrationsFS, databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("rolling back migrations: %w", err)
	}
	return nil
}

// MigrationStatus reports the current migration version and dirty flag, for
// readiness checks. A dirty database is not ready to serve.
func MigrationStatus(migrationsFS fs.FS, databaseURL string) (version uint, dirty bool, err error) {
	m, err := newMigrator(migrationsFS, databaseURL)
	if err != nil {
		return 0, false, err
	}
	defer m.Close()

	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}
