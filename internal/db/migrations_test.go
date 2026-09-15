package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func mustExec(t *testing.T, d *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := d.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func count(t *testing.T, d *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func userVersion(t *testing.T, d *sql.DB) int {
	t.Helper()
	var v int
	if err := d.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("PRAGMA user_version: %v", err)
	}
	return v
}

func TestOpenCreatesDataDirAndSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	d, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if _, err := os.Stat(filepath.Join(dir, "postlite.db")); err != nil {
		t.Fatalf("database file: %v", err)
	}

	for _, table := range []string{
		"users", "sessions", "collections", "folders", "requests",
		"environments", "secrets", "history", "settings",
	} {
		var name string
		err := d.QueryRow(
			"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %q is missing: %v", table, err)
		}
	}
}

func TestOpenEnablesWALAndForeignKeys(t *testing.T) {
	d := openTestDB(t)

	var mode string
	if err := d.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var fk int
	if err := d.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1 (cascades must be enforced)", fk)
	}
}

func TestMigrateSetsUserVersionAndIsIdempotent(t *testing.T) {
	d := openTestDB(t)

	if v := userVersion(t, d); v != len(migrations) {
		t.Fatalf("user_version = %d, want %d", v, len(migrations))
	}
	if err := Migrate(d); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if v := userVersion(t, d); v != len(migrations) {
		t.Errorf("user_version = %d after a repeated migration, want %d", v, len(migrations))
	}
	// Re-running must not duplicate the schema.
	if n := count(t, d, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'"); n != 1 {
		t.Errorf("found %d users tables, want 1", n)
	}
}

func TestOpenReopensExistingDatabase(t *testing.T) {
	dir := t.TempDir()

	d1, err := Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	mustExec(t, d1, "INSERT INTO settings (key, value) VALUES ('kept', 'yes')")
	if err := d1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	d2, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer d2.Close()
	if n := count(t, d2, "SELECT COUNT(*) FROM settings WHERE key = 'kept'"); n != 1 {
		t.Error("data did not survive a reopen")
	}
}

func TestFailedMigrationRollsBackAndKeepsVersion(t *testing.T) {
	d := openTestDB(t)
	applied := len(migrations)

	orig := migrations
	defer func() { migrations = orig }()
	migrations = append(append([]string{}, orig...), "CREATE TABLE broken (")

	if err := Migrate(d); err == nil {
		t.Fatal("Migrate accepted invalid SQL")
	}
	if v := userVersion(t, d); v != applied {
		t.Errorf("user_version = %d after a failed migration, want %d", v, applied)
	}
	if n := count(t, d, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'broken'"); n != 0 {
		t.Error("a partially applied migration left objects behind")
	}
}

func TestSecretsTableStoresCiphertextOnly(t *testing.T) {
	d := openTestDB(t)

	rows, err := d.Query("PRAGMA table_info(secrets)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(secrets): %v", err)
	}
	defer rows.Close()

	types := map[string]string{}
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		types[name] = ctype
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}

	want := map[string]bool{
		"id": true, "name": true, "ciphertext": true,
		"created_by": true, "created_at": true, "updated_at": true,
	}
	for col := range want {
		if _, ok := types[col]; !ok {
			t.Errorf("secrets is missing column %q", col)
		}
	}
	for col, ctype := range types {
		if !want[col] {
			t.Errorf("secrets has an unexpected column %q (%s); it must hold no plaintext", col, ctype)
		}
		if lc := strings.ToLower(col); strings.Contains(lc, "value") || strings.Contains(lc, "plain") {
			t.Errorf("secrets column %q looks like a plaintext column", col)
		}
	}
	if ctype := types["ciphertext"]; !strings.EqualFold(ctype, "BLOB") {
		t.Errorf("ciphertext column type = %q, want BLOB", ctype)
	}
}

func TestForeignKeysCascade(t *testing.T) {
	d := openTestDB(t)
	const ts = "2026-01-01T00:00:00Z"

	mustExec(t, d, `INSERT INTO users (id, username, password_hash, salt, enabled, role, created_at)
		VALUES (1, 'alice', 'hash', 'salt', 1, 'user', ?)`, ts)
	mustExec(t, d, `INSERT INTO collections (id, name, owner_id, created_at) VALUES (1, 'c', 1, ?)`, ts)
	mustExec(t, d, `INSERT INTO folders (id, collection_id, parent_id, name) VALUES (1, 1, NULL, 'f')`)
	mustExec(t, d, `INSERT INTO requests (id, collection_id, folder_id, owner_id, name, method, url, body_type, updated_at)
		VALUES (1, 1, 1, 1, 'r', 'GET', 'http://10.0.0.1/x', 'none', ?)`, ts)
	mustExec(t, d, `INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ('s1', 1, ?, ?)`, ts, ts)
	mustExec(t, d, `INSERT INTO environments (id, name, scope, owner_id, vars) VALUES (1, 'env', 'user', 1, '{}')`)

	// Deleting a collection cascades to its folders and requests.
	mustExec(t, d, "DELETE FROM collections WHERE id = 1")
	if n := count(t, d, "SELECT COUNT(*) FROM folders"); n != 0 {
		t.Errorf("folders = %d after the collection was deleted, want 0", n)
	}
	if n := count(t, d, "SELECT COUNT(*) FROM requests"); n != 0 {
		t.Errorf("requests = %d after the collection was deleted, want 0", n)
	}

	// Deleting a user cascades to sessions + owned environments and detaches
	// owned collections instead of deleting them.
	mustExec(t, d, `INSERT INTO collections (id, name, owner_id, created_at) VALUES (2, 'kept', 1, ?)`, ts)
	mustExec(t, d, "DELETE FROM users WHERE id = 1")
	if n := count(t, d, "SELECT COUNT(*) FROM sessions"); n != 0 {
		t.Errorf("sessions = %d after the user was deleted, want 0", n)
	}
	if n := count(t, d, "SELECT COUNT(*) FROM environments"); n != 0 {
		t.Errorf("environments = %d after the user was deleted, want 0", n)
	}
	if n := count(t, d, "SELECT COUNT(*) FROM collections WHERE id = 2 AND owner_id IS NULL"); n != 1 {
		t.Error("an owned collection should survive its owner with owner_id set to NULL")
	}
}

func TestConstraintsRejectInvalidRows(t *testing.T) {
	d := openTestDB(t)
	const ts = "2026-01-01T00:00:00Z"

	invalid := []struct {
		name  string
		query string
	}{
		{"role must be admin or user",
			`INSERT INTO users (username, password_hash, salt, enabled, role, created_at)
			 VALUES ('x', 'h', 's', 1, 'root', '` + ts + `')`},
		{"username must be unique",
			`INSERT INTO users (username, password_hash, salt, enabled, role, created_at)
			 VALUES ('dup', 'h', 's', 1, 'user', '` + ts + `')`},
		{"method must be a known verb",
			`INSERT INTO requests (collection_id, name, method, url, body_type, updated_at)
			 VALUES (1, 'r', 'TRACE', 'http://x', 'none', '` + ts + `')`},
		{"environment scope must be global or user",
			`INSERT INTO environments (name, scope, vars) VALUES ('e', 'team', '{}')`},
		{"secret name must be unique",
			`INSERT INTO secrets (name, ciphertext, created_by, created_at, updated_at)
			 VALUES ('dup-secret', x'00', 1, '` + ts + `', '` + ts + `')`},
	}

	// Seed the rows that the uniqueness cases collide with.
	mustExec(t, d, `INSERT INTO users (id, username, password_hash, salt, enabled, role, created_at)
		VALUES (1, 'dup', 'h', 's', 1, 'user', ?)`, ts)
	mustExec(t, d, `INSERT INTO collections (id, name, created_at) VALUES (1, 'c', ?)`, ts)
	mustExec(t, d, `INSERT INTO secrets (name, ciphertext, created_by, created_at, updated_at)
		VALUES ('dup-secret', x'00', 1, ?, ?)`, ts, ts)

	for _, tc := range invalid {
		if _, err := d.Exec(tc.query); err == nil {
			t.Errorf("%s: the insert was accepted", tc.name)
		}
	}

	// The same rows are valid once they stop colliding.
	if _, err := d.Exec(`INSERT INTO users (username, password_hash, salt, enabled, role, created_at)
		VALUES ('other', 'h', 's', 1, 'admin', ?)`, ts); err != nil {
		t.Errorf("valid admin user rejected: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO requests (collection_id, name, method, url, body_type, updated_at)
		VALUES (1, 'r', 'PATCH', 'http://x', 'none', ?)`, ts); err != nil {
		t.Errorf("valid PATCH request rejected: %v", err)
	}
}
