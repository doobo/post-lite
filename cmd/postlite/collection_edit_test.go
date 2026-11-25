package main

import (
	"net/http"
	"strconv"
	"testing"
)

func collPath(id int64) string { return "/api/collections/" + strconv.FormatInt(id, 10) }

func TestUpdateCollectionNameCategoryAndScope(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	alice := ts.cookie(ts.createUser("alice", "user", loginPassword))
	id := ts.createCollection(alice, "notes", false)

	// An owner can rename and categorise. Omitting `global` must not flip scope.
	if code, _, raw := ts.call("PUT", collPath(id), alice, map[string]any{
		"name": "renamed", "category": "dev",
	}); code != http.StatusOK {
		t.Fatalf("owner edit = %d (%s)", code, raw)
	}
	code, resp, raw := ts.call("GET", collPath(id), alice, nil)
	if code != http.StatusOK {
		t.Fatalf("get collection = %d (%s)", code, raw)
	}
	var got struct {
		Collection struct {
			Name     string `json:"name"`
			Category string `json:"category"`
			OwnerID  *int64 `json:"owner_id"`
		} `json:"collection"`
	}
	resp.decode(t, &got)
	if got.Collection.Name != "renamed" || got.Collection.Category != "dev" {
		t.Errorf("collection = %+v, want renamed/dev", got.Collection)
	}
	if got.Collection.OwnerID == nil {
		t.Error("omitting global turned a private collection global")
	}

	// Only an admin may change scope.
	if code, _, _ := ts.call("PUT", collPath(id), alice, map[string]any{
		"name": "renamed", "category": "dev", "global": true,
	}); code != http.StatusForbidden {
		t.Errorf("owner making collection global = %d, want 403", code)
	}
	if code, _, raw := ts.call("PUT", collPath(id), admin, map[string]any{
		"name": "renamed", "category": "dev", "global": true,
	}); code != http.StatusOK {
		t.Fatalf("admin making collection global = %d (%s)", code, raw)
	}
	code, resp, raw = ts.call("GET", collPath(id), alice, nil)
	if code != http.StatusOK {
		t.Fatalf("get global collection = %d (%s)", code, raw)
	}
	resp.decode(t, &got)
	if got.Collection.OwnerID != nil {
		t.Error("collection is still private after make-global")
	}

	// Creation accepts a category too.
	code, resp, raw = ts.call("POST", "/api/collections", admin, map[string]any{
		"name": "ops", "category": "infra", "global": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create with category = %d (%s)", code, raw)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &created)
	code, resp, raw = ts.call("GET", collPath(created.ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("get new collection = %d (%s)", code, raw)
	}
	resp.decode(t, &got)
	if got.Collection.Category != "infra" {
		t.Errorf("new category = %q, want infra", got.Collection.Category)
	}
}
