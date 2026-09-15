package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordingUpstream captures what the executed request actually put on the wire.
type recordingUpstream struct {
	srv         *httptest.Server
	mu          sync.Mutex
	contentType string
	body        string
}

func newRecordingUpstream(t *testing.T, reply string) *recordingUpstream {
	t.Helper()
	up := &recordingUpstream{}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.contentType = r.Header.Get("Content-Type")
		up.body = string(b)
		up.mu.Unlock()
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(up.srv.Close)
	return up
}

func (u *recordingUpstream) lastBody() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.body
}

func (u *recordingUpstream) lastContentType() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.contentType
}

func TestExecuteGraphQLComposesQueryAndVariables(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, `{"data":{"user":{"name":"ada"}}}`)

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":    "POST",
			"url":       up.srv.URL + "/graphql",
			"body_type": "graphql",
			"body":      `query User($id: ID!) { user(id: $id) { name } }`,
			"variables": `{"id":"{{who}}"}`,
		},
		"vars": map[string]string{"who": "42"},
	})
	if code != http.StatusOK {
		t.Fatalf("graphql execute = %d (%s)", code, raw)
	}
	var out struct {
		Body string `json:"body"`
	}
	resp.decode(t, &out)
	if !strings.Contains(out.Body, `"name":"ada"`) {
		t.Errorf("response body = %q, want the upstream JSON", out.Body)
	}

	if ct := up.lastContentType(); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("upstream Content-Type = %q, want application/json", ct)
	}
	var sent struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal([]byte(up.lastBody()), &sent); err != nil {
		t.Fatalf("upstream received %q, which is not the GraphQL envelope: %v", up.lastBody(), err)
	}
	if !strings.Contains(sent.Query, "query User($id: ID!)") {
		t.Errorf("query = %q, want the document as typed", sent.Query)
	}
	// {{who}} is resolved inside the variables document as well as the query.
	if sent.Variables["id"] != "42" {
		t.Errorf("variables = %v, want id resolved to \"42\"", sent.Variables)
	}
}

// A stored graphql request keeps its variables document; an empty one sends the
// minimal body.
func TestStoredGraphQLRequestRoundTrips(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	colID := ts.createCollection(admin, "gql", false)
	up := newRecordingUpstream(t, `{"data":null}`)

	const query = `query { me { name } }`
	code, resp, raw := ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": colID,
		"name":          "graphql-me",
		"method":        "POST",
		"url":           up.srv.URL + "/graphql",
		"body_type":     "graphql",
		"body":          query,
		"variables":     `{"limit":5}`,
	})
	if code != http.StatusCreated {
		t.Fatalf("create graphql request = %d (%s)", code, raw)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &created)

	var stored string
	if err := ts.db.QueryRow("SELECT COALESCE(variables,'') FROM requests WHERE id = ?", created.ID).Scan(&stored); err != nil {
		t.Fatalf("read variables: %v", err)
	}
	if stored != `{"limit":5}` {
		t.Errorf("stored variables = %q, want the document as typed", stored)
	}

	code, resp, raw = ts.call("GET", "/api/requests/"+idStr(created.ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("get request = %d (%s)", code, raw)
	}
	var fetched struct {
		BodyType  string `json:"body_type"`
		Variables string `json:"variables"`
	}
	resp.decode(t, &fetched)
	if fetched.BodyType != "graphql" || fetched.Variables != `{"limit":5}` {
		t.Errorf("GET returned body_type=%q variables=%q", fetched.BodyType, fetched.Variables)
	}

	if code, _, raw := ts.call("POST", "/api/execute", admin,
		map[string]any{"request_id": created.ID}); code != http.StatusOK {
		t.Fatalf("execute the stored graphql request = %d (%s)", code, raw)
	}
	if body := up.lastBody(); !strings.Contains(body, `"limit":5`) || !strings.Contains(body, query) {
		t.Errorf("upstream received %q, want the stored query and variables", body)
	}

	// Clearing the variables sends the query alone.
	if code, _, raw := ts.call("PUT", "/api/requests/"+idStr(created.ID), admin, map[string]any{
		"name": "graphql-me", "method": "POST", "url": up.srv.URL + "/graphql",
		"body_type": "graphql", "body": query, "variables": "",
	}); code != http.StatusOK {
		t.Fatalf("update graphql request = %d (%s)", code, raw)
	}
	if code, _, raw := ts.call("POST", "/api/execute", admin,
		map[string]any{"request_id": created.ID}); code != http.StatusOK {
		t.Fatalf("execute after clearing variables = %d (%s)", code, raw)
	}
	if body := up.lastBody(); strings.Contains(body, "variables") {
		t.Errorf("upstream received %q, want no variables key", body)
	}
}

func TestExecuteGraphQLRejectsBadVariables(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, `{"data":null}`)

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method": "POST", "url": up.srv.URL + "/graphql", "body_type": "graphql",
			"body": `query { me { name } }`, "variables": `id=42`,
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("graphql with non-JSON variables = %d, want 400 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "bad_request" {
		t.Errorf("error = %+v, want code bad_request", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "variables") {
		t.Errorf("message = %q, want it to point at the variables document", resp.Error.Message)
	}
	if body := up.lastBody(); body != "" {
		t.Errorf("a rejected graphql body still reached the upstream: %q", body)
	}
}

func TestRequestsRejectUnknownBodyType(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	colID := ts.createCollection(admin, "types", false)

	base := map[string]any{
		"collection_id": colID, "name": "x", "method": "POST", "url": "http://10.0.0.1/x",
	}
	for _, bad := range []string{"form-data", "GRAPHQL", "xml"} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["body_type"] = bad
		code, resp, raw := ts.call("POST", "/api/requests", admin, body)
		if code != http.StatusBadRequest {
			t.Errorf("create with body_type=%q = %d, want 400 (%s)", bad, code, raw)
			continue
		}
		if resp.Error == nil || resp.Error.Code != "bad_request" {
			t.Errorf("create with body_type=%q error = %+v, want bad_request", bad, resp.Error)
		}
	}

	// The four supported types are accepted, including the new one.
	for _, good := range []string{"none", "json", "raw", "graphql"} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["body_type"] = good
		if code, _, raw := ts.call("POST", "/api/requests", admin, body); code != http.StatusCreated {
			t.Errorf("create with body_type=%q = %d, want 201 (%s)", good, code, raw)
		}
	}
}
