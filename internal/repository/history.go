package repository

import (
	"database/sql"
	"errors"
	"time"

	"postlite/internal/models"
)

type History struct{ db *sql.DB }

func NewHistory(db *sql.DB) *History { return &History{db: db} }

func (r *History) Insert(requestID *int64, userID int64, method, url string, status int, durMS int64, reqText, resText string) (int64, error) {
	res, err := r.db.Exec(`
		INSERT INTO history (request_id, user_id, method, url, status, duration_ms, req_redacted, res_redacted, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		sql.NullInt64{Valid: requestID != nil, Int64: derefInt64(requestID)},
		userID, method, url, status, durMS, nullStr(reqText), nullStr(resText), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// List returns history for a user, optionally filtered by request.
func (r *History) List(userID int64, requestID *int64, limit int) ([]*models.HistoryItem, error) {
	q := `SELECT id, request_id, user_id, method, url, status, duration_ms,
			COALESCE(req_redacted,''), COALESCE(res_redacted,''), created_at
			FROM history WHERE user_id = ?`
	args := []any{userID}
	if requestID != nil {
		q += " AND request_id = ?"
		args = append(args, *requestID)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := r.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectHistory(rows)
}

func (r *History) Get(id, userID int64) (*models.HistoryItem, error) {
	row := r.db.QueryRow(`
		SELECT id, request_id, user_id, method, url, status, duration_ms,
		       COALESCE(req_redacted,''), COALESCE(res_redacted,''), created_at
		FROM history WHERE id = ? AND user_id = ?`, id, userID)
	h, err := scanHistory(row)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (r *History) Delete(id, userID int64) error {
	_, err := r.db.Exec("DELETE FROM history WHERE id = ? AND user_id = ?", id, userID)
	return err
}

// Purge keeps only the most recent keep rows (global cap).
func (r *History) Purge(keep int) error {
	if keep <= 0 {
		return nil
	}
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM history").Scan(&total); err != nil {
		return err
	}
	if total <= keep {
		return nil
	}
	_, err := r.db.Exec(
		`DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT ?)`, keep)
	return err
}

func collectHistory(rows *sql.Rows) ([]*models.HistoryItem, error) {
	var out []*models.HistoryItem
	for rows.Next() {
		h, err := scanHistory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func scanHistory(row Scanner) (*models.HistoryItem, error) {
	var h models.HistoryItem
	var reqID sql.NullInt64
	var createdAt string
	err := row.Scan(&h.ID, &reqID, &h.UserID, &h.Method, &h.URL, &h.Status, &h.DurationMS, &h.ReqText, &h.ResText, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if reqID.Valid {
		v := reqID.Int64
		h.RequestID = &v
	}
	if t, perr := time.Parse(time.RFC3339, createdAt); perr == nil {
		h.CreatedAt = t
	}
	return &h, nil
}
