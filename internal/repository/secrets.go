package repository

import (
	"database/sql"
	"errors"
	"time"

	"postlite/internal/models"
)

type Secrets struct{ db *sql.DB }

func NewSecrets(db *sql.DB) *Secrets { return &Secrets{db: db} }

// Create writes a new secret (name must be unique).
func (r *Secrets) Create(name string, ciphertext []byte, createdBy int64) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO secrets (name, ciphertext, created_by, created_at, updated_at) VALUES (?,?,?,?,?)",
		name, ciphertext, createdBy, now(), now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update replaces the ciphertext for an existing secret name.
func (r *Secrets) Update(name string, ciphertext []byte) error {
	res, err := r.db.Exec("UPDATE secrets SET ciphertext=?, updated_at=? WHERE name=?", ciphertext, now(), name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns metadata only: id + name + updated_at. Never ciphertext.
func (r *Secrets) List() ([]*models.SecretMeta, error) {
	rows, err := r.db.Query("SELECT id, name, updated_at FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.SecretMeta
	for rows.Next() {
		var s models.SecretMeta
		var updatedAt string
		if err := rows.Scan(&s.ID, &s.Name, &updatedAt); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339, updatedAt); perr == nil {
			s.UpdatedAt = t
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// GetByName returns the ciphertext blob (or ok=false). Callers decrypt via Vault.
func (r *Secrets) GetByName(name string) (blob []byte, ok bool, err error) {
	err = r.db.QueryRow("SELECT ciphertext FROM secrets WHERE name = ?", name).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return blob, true, nil
}

func (r *Secrets) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM secrets WHERE id = ?", id)
	return err
}
