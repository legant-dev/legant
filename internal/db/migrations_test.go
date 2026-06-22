package db_test

import (
	"io/fs"
	"regexp"
	"testing"

	legant "github.com/legant-dev/legant"
)

var migName = regexp.MustCompile(`^(\d+)_.+\.(up|down)\.sql$`)

// TestMigrationsWellFormed enforces that every migration file is named
// NNNN_name.(up|down).sql, that no two migrations share a version number (the
// "000006 collision" class of merge bug), and that every up has a matching down.
// This runs as a plain unit test so the check happens on every CI run.
func TestMigrationsWellFormed(t *testing.T) {
	entries, err := fs.ReadDir(legant.MigrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}

	ups := map[string]string{}
	downs := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migName.FindStringSubmatch(e.Name())
		if m == nil {
			t.Fatalf("migration %q does not match NNNN_name.(up|down).sql", e.Name())
		}
		ver, dir := m[1], m[2]
		seen := ups
		if dir == "down" {
			seen = downs
		}
		if prev, ok := seen[ver]; ok {
			t.Fatalf("duplicate %s migration for version %s: %s and %s", dir, ver, prev, e.Name())
		}
		seen[ver] = e.Name()
	}

	for ver, up := range ups {
		if _, ok := downs[ver]; !ok {
			t.Fatalf("up migration %s has no matching down", up)
		}
	}
	for ver, down := range downs {
		if _, ok := ups[ver]; !ok {
			t.Fatalf("down migration %s has no matching up", down)
		}
	}
}
