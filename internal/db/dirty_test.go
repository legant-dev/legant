package db_test

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/db"
)

// A dirty schema (a migration that failed mid-way) must block further migrations
// and be reported as not-ready, rather than being silently retried. Runs against
// the isolated round-trip database so flipping the dirty flag can't affect the
// shared integration database.
func TestRunMigrationsRefusesDirty(t *testing.T) {
	url := os.Getenv("LEGANT_MIGRATE_ROUNDTRIP_URL")
	if url == "" {
		t.Skip("LEGANT_MIGRATE_ROUNDTRIP_URL not set; skipping dirty-schema test")
	}
	migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations(migFS, url); err != nil {
		t.Fatalf("baseline up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Reset the dirty flag via a fresh connection so the cleanup works even after
	// the pool above is closed and regardless of a t.Fatal — otherwise a leftover
	// dirty flag would break every later migration test.
	t.Cleanup(func() {
		p, err := pgxpool.New(context.Background(), url)
		if err != nil {
			return
		}
		defer p.Close()
		_, _ = p.Exec(context.Background(), `UPDATE schema_migrations SET dirty = false`)
	})

	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatal(err)
	}

	if err := db.RunMigrations(migFS, url); err == nil {
		t.Fatal("RunMigrations must refuse to run on a dirty schema")
	}
	if _, dirty, err := db.MigrationStatus(migFS, url); err != nil {
		t.Fatal(err)
	} else if !dirty {
		t.Fatal("MigrationStatus should report dirty=true")
	}
}
