package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"postlite/internal/models"
)

type Requests struct{ db *sql.DB }

func NewRequests(db *sql.DB) *Requests { return &Requests{db: db} }

// RequestPayload is the create/update body; headers/query are held as JSON.
type RequestPayload struct {
	CollectionID int64  `json:"collection_id"`
	FolderID     *int64 `json:"folder_id"`
	Name         string `json:"name"`
	// Protocol: http (default), ws, sse. Empty means http for old clients.
	Protocol string `json:"protocol"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Headers  string `json:"headers"`
	Query    string `json:"query"`
	BodyType string `json:"body_type"`
	Body     string `json:"body"`
	// Variables is the GraphQL variables document (body_type=graphql).
	Variables string `json:"variables"`
	// UseProxy routes this request through the admin-configured proxy_url.
	// Off by default: a proxy is opt-in per request.
	UseProxy bool `json:"use_proxy"`
}

func (p *RequestPayload) HeadersMap() map[string]string {
	m := map[string]string{}
	if p.Headers != "" {
		_ = json.Unmarshal([]byte(p.Headers), &m)
	}
	return m
}

// QueryPairs parses the query JSON: [{"k":"","v":""}].
func (p *RequestPayload) QueryPairs() [][2]string {
	var arr []struct {
		K string `json:"k"`
		V string `json:"v"`
	}
	if p.Query != "" {
		_ = json.Unmarshal([]byte(p.Query), &arr)
	}
	out := make([][2]string, 0, len(arr))
	for _, q := range arr {
		out = append(out, [2]string{q.K, q.V})
	}
	return out
}

func (r *Requests) Create(in RequestPayload, owner *int64) (int64, error) {
	res, err := r.db.Exec(
		"INSERT INTO requests (collection_id, folder_id, owner_id, name, protocol, method, url, headers, query, body_type, body, variables, use_proxy, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		in.CollectionID,
		sql.NullInt64{Valid: in.FolderID != nil, Int64: derefInt64(in.FolderID)},
		sql.NullInt64{Valid: owner != nil, Int64: derefInt64(owner)},
		in.Name, orDefault(in.Protocol, "http"), in.Method, in.URL, nullStr(in.Headers), nullStr(in.Query),
		orDefault(in.BodyType, "none"), nullStr(in.Body), nullStr(in.Variables), boolInt(in.UseProxy), now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *Requests) Get(id int64) (*models.Request, error) {
	row := r.db.QueryRow(`
		SELECT id, collection_id, folder_id, owner_id, name, protocol, method, url,
		       COALESCE(headers,''), COALESCE(query,''), body_type, COALESCE(body,''),
		       COALESCE(variables,''), use_proxy, updated_at
		FROM requests WHERE id = ?`, id)
	req, err := scanRequest(row)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (r *Requests) List(collectionID int64) ([]*models.Request, error) {
	rows, err := r.db.Query(`
		SELECT id, collection_id, folder_id, owner_id, name, protocol, method, url,
		       COALESCE(headers,''), COALESCE(query,''), body_type, COALESCE(body,''),
		       COALESCE(variables,''), use_proxy, updated_at
		FROM requests WHERE collection_id = ? ORDER BY id`, collectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Request
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, req)
	}
	return out, rows.Err()
}

func (r *Requests) Update(id int64, in RequestPayload) error {
	_, err := r.db.Exec(`
		UPDATE requests
		SET collection_id=?, folder_id=?, name=?, protocol=?, method=?, url=?, headers=?, query=?, body_type=?, body=?,
		    variables=?, use_proxy=?, updated_at=?
		WHERE id=?`,
		in.CollectionID,
		sql.NullInt64{Valid: in.FolderID != nil, Int64: derefInt64(in.FolderID)},
		in.Name, orDefault(in.Protocol, "http"), in.Method, in.URL, nullStr(in.Headers), nullStr(in.Query),
		orDefault(in.BodyType, "none"), nullStr(in.Body), nullStr(in.Variables), boolInt(in.UseProxy), now(), id,
	)
	return err
}

func (r *Requests) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM requests WHERE id = ?", id)
	return err
}

func scanRequest(row Scanner) (*models.Request, error) {
	var req models.Request
	var folder, owner sql.NullInt64
	var useProxy int
	var updatedAt string
	err := row.Scan(
		&req.ID, &req.CollectionID, &folder, &owner, &req.Name, &req.Protocol, &req.Method, &req.URL,
		&req.Headers, &req.Query, &req.BodyType, &req.Body, &req.Variables, &useProxy, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if folder.Valid {
		v := folder.Int64
		req.FolderID = &v
	}
	if owner.Valid {
		v := owner.Int64
		req.OwnerID = &v
	}
	req.UseProxy = useProxy != 0
	if req.Protocol == "" {
		req.Protocol = "http"
	}
	if t, perr := time.Parse(time.RFC3339, updatedAt); perr == nil {
		req.UpdatedAt = t
	}
	return &req, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
