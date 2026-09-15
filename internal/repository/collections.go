package repository

import (
	"database/sql"
	"errors"
	"time"

	"postlite/internal/models"
)

type Collections struct{ db *sql.DB }

func NewCollections(db *sql.DB) *Collections { return &Collections{db: db} }

func (r *Collections) Create(name string, owner *int64) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO collections (name, owner_id, created_at) VALUES (?,?,?)",
		name, sql.NullInt64{Valid: owner != nil, Int64: derefInt64(owner)}, now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *Collections) Get(id int64) (*models.Collection, error) {
	row := r.db.QueryRow("SELECT id, name, owner_id, created_at FROM collections WHERE id = ?", id)
	c, err := scanCollection(row)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListFor returns collections visible to u: admin sees all, others see
// global (owner NULL) plus their own.
func (r *Collections) ListFor(u models.User) ([]*models.Collection, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if u.Role == "admin" {
		rows, err = r.db.Query("SELECT id, name, owner_id, created_at FROM collections ORDER BY id")
	} else {
		rows, err = r.db.Query(
			"SELECT id, name, owner_id, created_at FROM collections WHERE owner_id IS NULL OR owner_id = ? ORDER BY id",
			u.ID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Collection
	for rows.Next() {
		c, err := scanCollection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Collections) UpdateName(id int64, name string) error {
	_, err := r.db.Exec("UPDATE collections SET name = ? WHERE id = ?", name, id)
	return err
}

func (r *Collections) Delete(id int64) error {
	// folders/requests cascade via ON DELETE CASCADE (PRAGMA foreign_keys=1)
	_, err := r.db.Exec("DELETE FROM collections WHERE id = ?", id)
	return err
}

// CanView: admin all; global collections visible to all; owned to owner.
func (r *Collections) CanView(u models.User, c *models.Collection) bool {
	if u.Role == "admin" {
		return true
	}
	if c.OwnerID == nil {
		return true
	}
	return *c.OwnerID == u.ID
}

// CanManage: admin all; owners manage their own.
func (r *Collections) CanManage(u models.User, c *models.Collection) bool {
	if u.Role == "admin" {
		return true
	}
	return c.OwnerID != nil && *c.OwnerID == u.ID
}

type Folders struct{ db *sql.DB }

func NewFolders(db *sql.DB) *Folders { return &Folders{db: db} }

func (r *Folders) Create(collectionID int64, parent *int64, name string) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO folders (collection_id, parent_id, name) VALUES (?,?,?)",
		collectionID, sql.NullInt64{Valid: parent != nil, Int64: derefInt64(parent)}, name,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *Folders) List(collectionID int64) ([]*models.Folder, error) {
	rows, err := r.db.Query(
		"SELECT id, collection_id, parent_id, name FROM folders WHERE collection_id = ? ORDER BY id",
		collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Folder
	for rows.Next() {
		var f models.Folder
		var parent sql.NullInt64
		if err := rows.Scan(&f.ID, &f.CollectionID, &parent, &f.Name); err != nil {
			return nil, err
		}
		if parent.Valid {
			v := parent.Int64
			f.ParentID = &v
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

func (r *Folders) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM folders WHERE id = ?", id)
	return err
}

func scanCollection(row Scanner) (*models.Collection, error) {
	var c models.Collection
	var owner sql.NullInt64
	var createdAt string
	err := row.Scan(&c.ID, &c.Name, &owner, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if owner.Valid {
		v := owner.Int64
		c.OwnerID = &v
	}
	if t, perr := time.Parse(time.RFC3339, createdAt); perr == nil {
		c.CreatedAt = t
	}
	return &c, nil
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
