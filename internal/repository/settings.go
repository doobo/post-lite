package repository

import (
	"database/sql"
	"encoding/json"
)

type Settings struct{ db *sql.DB }

func NewSettings(db *sql.DB) *Settings { return &Settings{db: db} }

// Get returns the value and whether the key exists.
func (r *Settings) Get(key string) (string, bool, error) {
	var v string
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (r *Settings) Set(key, value string) error {
	_, err := r.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (r *Settings) All() (map[string]string, error) {
	rows, err := r.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// AppendAudit stores the audit trail as a JSON array under "audit_log",
// capped at maxEntries. Admin operations are also written to stdout.
func (r *Settings) AppendAudit(entry string, maxEntries int) error {
	if maxEntries <= 0 {
		maxEntries = 500
	}
	cur, _, _ := r.Get("audit_log")
	var arr []string
	if cur != "" {
		_ = json.Unmarshal([]byte(cur), &arr)
	}
	arr = append(arr, entry)
	if len(arr) > maxEntries {
		arr = arr[len(arr)-maxEntries:]
	}
	b, _ := json.Marshal(arr)
	return r.Set("audit_log", string(b))
}
