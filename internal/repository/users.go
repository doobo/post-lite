package repository

import (
	"database/sql"
	"errors"
	"time"

	"postlite/internal/models"
)

func now() string { return time.Now().UTC().Format(time.RFC3339) }

var ErrNotFound = errors.New("not found")

type Users struct{ db *sql.DB }

func NewUsers(db *sql.DB) *Users { return &Users{db: db} }

func (r *Users) Create(username, role, saltHex, hashHex string) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO users (username, password_hash, salt, enabled, role, created_at) VALUES (?,?,?,1,?,?)",
		username, hashHex, saltHex, role, now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *Users) GetByID(id int64) (*models.User, error) {
	row := r.db.QueryRow(
		"SELECT id, username, password_hash, salt, enabled, role, created_at FROM users WHERE id = ?", id)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Users) GetByUsername(username string) (*models.User, error) {
	row := r.db.QueryRow(
		"SELECT id, username, password_hash, salt, enabled, role, created_at FROM users WHERE username = ?", username)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Users) List() ([]*models.User, error) {
	rows, err := r.db.Query("SELECT id, username, password_hash, salt, enabled, role, created_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *Users) Count() (int, error) {
	var n int
	err := r.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (r *Users) SetPassword(id int64, saltHex, hashHex string) error {
	_, err := r.db.Exec("UPDATE users SET salt = ?, password_hash = ? WHERE id = ?", saltHex, hashHex, id)
	return err
}

func (r *Users) SetEnabled(id int64, enabled bool) error {
	_, err := r.db.Exec("UPDATE users SET enabled = ? WHERE id = ?", enabled, id)
	return err
}

func (r *Users) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

type Scanner interface {
	Scan(...any) error
}

func scanUser(row Scanner) (*models.User, error) {
	var (
		u         models.User
		enabled   int
		createdAt string
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &enabled, &u.Role, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	t, perr := time.Parse(time.RFC3339, createdAt)
	if perr == nil {
		u.CreatedAt = t
	}
	return &u, nil
}
