package db

import (
	"database/sql"
	"fmt"
)

var migrations = []string{migrationV1, migrationV2, migrationV3, migrationV4}

const migrationV1 = `
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  role          TEXT NOT NULL CHECK(role IN ('admin','user')),
  created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE collections (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  owner_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE folders (
  id            INTEGER PRIMARY KEY,
  collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  parent_id     INTEGER REFERENCES folders(id) ON DELETE CASCADE,
  name          TEXT NOT NULL
);

CREATE TABLE requests (
  id            INTEGER PRIMARY KEY,
  collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  folder_id     INTEGER REFERENCES folders(id) ON DELETE SET NULL,
  owner_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name          TEXT NOT NULL,
  method        TEXT NOT NULL CHECK(method IN ('GET','POST','PUT','PATCH','DELETE')),
  url           TEXT NOT NULL,
  headers       TEXT,
  query         TEXT,
  body_type     TEXT NOT NULL DEFAULT 'none',
  body          TEXT,
  updated_at    TEXT NOT NULL
);

CREATE TABLE environments (
  id       INTEGER PRIMARY KEY,
  name     TEXT NOT NULL,
  scope    TEXT NOT NULL CHECK(scope IN ('global','user')),
  owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  vars     TEXT NOT NULL,
  UNIQUE(scope, owner_id, name)
);

CREATE TABLE secrets (
  id         INTEGER PRIMARY KEY,
  name       TEXT UNIQUE NOT NULL,
  ciphertext BLOB NOT NULL,
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE history (
  id           INTEGER PRIMARY KEY,
  request_id   INTEGER,
  user_id      INTEGER NOT NULL,
  method       TEXT NOT NULL,
  url          TEXT NOT NULL,
  status       INTEGER NOT NULL,
  duration_ms  INTEGER NOT NULL,
  req_redacted TEXT,
  res_redacted TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// migrationV2 adds the per-request "send this one through the configured proxy"
// flag. Existing rows default to 0 = direct, which is also the UI default, so an
// upgrade never starts routing traffic somewhere new.
const migrationV2 = `
ALTER TABLE requests ADD COLUMN use_proxy INTEGER NOT NULL DEFAULT 0;
`

// migrationV3 adds the GraphQL variables document. It is a separate column
// rather than a second body so body_type=graphql keeps the query in `body`
// (what a plain editor would show) and the variables stay JSON-checked on send.
const migrationV3 = `
ALTER TABLE requests ADD COLUMN variables TEXT;
`

// migrationV4 adds the realtime protocol discriminator. HTTP stays the
// default; ws/sse rows reuse method=GET (so the V1 method CHECK keeps
// holding) and carry their extra options in the same columns the editor
// already has (body = initial message / SSE event filter lives in variables).
// Socket.IO / MQTT will extend this column later, no new table needed.
const migrationV4 = `
ALTER TABLE requests ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';
`

func Migrate(db *sql.DB) error {
	var current int
	if err := db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	for i := current + 1; i <= len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
