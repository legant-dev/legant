// Package testsupport provides shared helpers for integration tests that need a
// real Postgres database.
package testsupport

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/db"
)

// EnvURL points at a Postgres the tests may create throwaway databases on.
const EnvURL = "LEGANT_TEST_DATABASE_URL"

var dbCounter atomic.Int64

// DB provisions a fresh, migrated, throwaway database for the calling test and
// returns a pool to it. Each call gets its own database (dropped at cleanup), so
// integration tests are fully isolated and safe to run in parallel across
// packages — even when they reset shared tables like signing_keys. The test is
// skipped when LEGANT_TEST_DATABASE_URL is unset (unless LEGANT_REQUIRE_DB is
// set, e.g. in CI, where an unset URL is a hard failure).
func DB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	baseURL := os.Getenv(EnvURL)
	if baseURL == "" {
		if os.Getenv("LEGANT_REQUIRE_DB") != "" {
			t.Fatalf("%s not set but LEGANT_REQUIRE_DB is set; refusing to skip integration test", EnvURL)
		}
		t.Skipf("%s not set; skipping Postgres integration test", EnvURL)
	}

	name := fmt.Sprintf("legant_it_p%d_%d", os.Getpid(), dbCounter.Add(1))
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, baseURL)
	if err != nil {
		t.Fatalf("connecting to admin database: %v", err)
	}
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
		admin.Close()
		t.Fatalf("dropping stale test database: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("creating test database: %v", err)
	}
	admin.Close()

	testURL := withDBName(t, baseURL, name)
	migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	if err := db.RunMigrations(migFS, testURL); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	pool, err := pgxpool.New(ctx, testURL)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		a, err := pgxpool.New(context.Background(), baseURL)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return pool
}

func withDBName(t *testing.T, base, name string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parsing %s: %v", EnvURL, err)
	}
	u.Path = "/" + name
	return u.String()
}

// Truncate empties the given tables (resetting identities). With per-test
// database isolation this is rarely needed, but remains for tests that reset
// state mid-run.
func Truncate(t *testing.T, pool *pgxpool.Pool, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		return
	}
	stmt := "TRUNCATE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE"
	if _, err := pool.Exec(context.Background(), stmt); err != nil {
		t.Fatalf("truncating %v: %v", tables, err)
	}
}
