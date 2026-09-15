package models

import "time"

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Salt         string    `json:"-"`
	PasswordHash string    `json:"-"`
	Enabled      bool      `json:"enabled"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"-"`
	UserID    int64     `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

type Collection struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	OwnerID   *int64    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Folder struct {
	ID           int64  `json:"id"`
	CollectionID int64  `json:"collection_id"`
	ParentID     *int64 `json:"parent_id"`
	Name         string `json:"name"`
}

type Request struct {
	ID           int64  `json:"id"`
	CollectionID int64  `json:"collection_id"`
	FolderID     *int64 `json:"folder_id"`
	OwnerID      *int64 `json:"owner_id"`
	Name         string `json:"name"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	Headers      string `json:"headers"`
	Query        string `json:"query"`
	BodyType     string `json:"body_type"`
	Body         string `json:"body"`
	// Variables is the GraphQL variables document; only used when BodyType is
	// "graphql", and kept as text so the editor can show what the user typed.
	Variables string    `json:"variables"`
	UseProxy  bool      `json:"use_proxy"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Environment struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	OwnerID *int64 `json:"owner_id"`
	Vars    string `json:"vars"`
}

type SecretMeta struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

type HistoryItem struct {
	ID         int64     `json:"id"`
	RequestID  *int64    `json:"request_id"`
	UserID     int64     `json:"user_id"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	Status     int       `json:"status"`
	DurationMS int64     `json:"duration_ms"`
	ReqText    string    `json:"req_redacted"`
	ResText    string    `json:"res_redacted"`
	CreatedAt  time.Time `json:"created_at"`
}
