package repository

import (
	"database/sql"
	"errors"
	"time"

	"postlite/internal/models"
)

type Sessions struct{ db *sql.DB }

func NewSessions(db *sql.DB) *Sessions { return &Sessions{db: db} }

func (r *Sessions) Create(tokenHash string, userID int64, ttl time.Duration) error {
	_, err := r.db.Exec(
		"INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
		tokenHash, userID, now(), time.Now().UTC().Add(ttl).Format(time.RFC3339),
	)
	return err
}

func (r *Sessions) Get(tokenHash string) (*models.Session, error) {
	var s models.Session
	var createdAt, expiresAt string
	err := r.db.QueryRow("SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?", tokenHash).
		Scan(&s.ID, &s.UserID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t, perr := time.Parse(time.RFC3339, expiresAt); perr == nil {
		s.ExpiresAt = t
	}
	return &s, nil
}

func (r *Sessions) Delete(tokenHash string) error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE id = ?", tokenHash)
	return err
}

func (r *Sessions) PurgeExpired() error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE expires_at < ?", now())
	return err
}
