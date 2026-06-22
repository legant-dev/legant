package db_test

import (
	"io/fs"
	"os"
	"testing"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/db"
)

// TestMigrationRoundTrip applies all migrations, rolls them all the way back,
// and re-applies them — proving every down migration is a correct inverse of its
// up. It runs against its OWN database (LEGANT_MIGRATE_ROUNDTRIP_URL) because
// rolling fully down would destroy the shared integration database; CI provisions
// a dedicated database for it.
func TestMigrationRoundTrip(t *testing.T) {
	url := os.Getenv("LEGANT_MIGRATE_ROUNDTRIP_URL")
	if url == "" {
		t.Skip("LEGANT_MIGRATE_ROUNDTRIP_URL not set; skipping migration round-trip")
	}
	migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.RunMigrations(migFS, url); err != nil {
		t.Fatalf("initial up: %v", err)
	}
	if err := db.MigrateDownAll(migFS, url); err != nil {
		t.Fatalf("down all: %v", err)
	}
	if err := db.RunMigrations(migFS, url); err != nil {
		t.Fatalf("up again after down: %v", err)
	}
}
