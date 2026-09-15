package repository

import (
	"database/sql"
	"errors"

	"postlite/internal/models"
)

type Environments struct{ db *sql.DB }

func NewEnvironments(db *sql.DB) *Environments { return &Environments{db: db} }

func (r *Environments) Create(name, scope string, owner *int64, vars string) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO environments (name, scope, owner_id, vars) VALUES (?,?,?,?)",
		name, scope, sql.NullInt64{Valid: owner != nil, Int64: derefInt64(owner)}, vars,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *Environments) Get(id int64) (*models.Environment, error) {
	row := r.db.QueryRow("SELECT id, name, scope, owner_id, vars FROM environments WHERE id = ?", id)
	e, err := scanEnvironment(row)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// ListFor: admin all, others global + own user-scoped envs.
func (r *Environments) ListFor(u models.User) ([]*models.Environment, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if u.Role == "admin" {
		rows, err = r.db.Query("SELECT id, name, scope, owner_id, vars FROM environments ORDER BY id")
	} else {
		rows, err = r.db.Query(
			"SELECT id, name, scope, owner_id, vars FROM environments WHERE scope='global' OR (scope='user' AND owner_id=?) ORDER BY id",
			u.ID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Environment
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *Environments) Update(id int64, name, vars string) error {
	_, err := r.db.Exec("UPDATE environments SET name=?, vars=? WHERE id=?", name, vars, id)
	return err
}

func (r *Environments) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM environments WHERE id = ?", id)
	return err
}

// CanView: admin all; global visible to all; user-scoped to owner only.
func (r *Environments) CanView(u models.User, e *models.Environment) bool {
	if u.Role == "admin" {
		return true
	}
	if e.Scope == "global" {
		return true
	}
	return e.OwnerID != nil && *e.OwnerID == u.ID
}

func (r *Environments) CanManage(u models.User, e *models.Environment) bool {
	if u.Role == "admin" {
		return true
	}
	if e.Scope == "global" {
		return false
	}
	return e.OwnerID != nil && *e.OwnerID == u.ID
}

func scanEnvironment(row Scanner) (*models.Environment, error) {
	var e models.Environment
	var owner sql.NullInt64
	err := row.Scan(&e.ID, &e.Name, &e.Scope, &owner, &e.Vars)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if owner.Valid {
		v := owner.Int64
		e.OwnerID = &v
	}
	return &e, nil
}
