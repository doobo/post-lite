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
	// Protocol is the realtime discriminator: http (default), ws, sse.
	// Socket.IO / MQTT will extend this column later. HTTP rows keep the
	// existing method/body_type semantics; ws/sse rows use method=GET and
	// carry subprotocol / event filter in body/variables (see migrationV4).
	Protocol string `json:"protocol"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Headers  string `json:"headers"`
	Query    string `json:"query"`
	BodyType string `json:"body_type"`
	Body     string `json:"body"`
	// Variables is the GraphQL variables document; only used when BodyType is
	// "graphql", and kept as text so the editor can show what the user typed.
	Variables string `json:"variables"`
	// Script is the pre-request script (JS), run server-side in the sandbox
	// before {{VAR}} resolution. Empty means "no script".
	Script string `json:"script"`
	// TestScript is the post-response script (JS): pm.response assertions and
	// pm.test results, run after the response comes back and is redacted.
	TestScript string    `json:"test_script"`
	UseProxy   bool      `json:"use_proxy"`
	UpdatedAt  time.Time `json:"updated_at"`
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
