package repository

import (
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"postlite/internal/db"
	"postlite/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	sdb, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	return New(sdb)
}

func mkUser(t *testing.T, st *Store, username, role string) models.User {
	t.Helper()
	id, err := st.Users.Create(username, role, "salt-"+username, "hash-"+username)
	if err != nil {
		t.Fatalf("create user %q: %v", username, err)
	}
	u, err := st.Users.GetByID(id)
	if err != nil {
		t.Fatalf("get user %q: %v", username, err)
	}
	return *u
}

func ptr(n int64) *int64 { return &n }

func sameSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) != len(w) {
		t.Fatalf("%s = %v, want %v", label, g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("%s = %v, want %v", label, g, w)
		}
	}
}

func collectionNames(cols []*models.Collection) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, c.Name)
	}
	return out
}

func environmentNames(envs []*models.Environment) []string {
	out := make([]string, 0, len(envs))
	for _, e := range envs {
		out = append(out, e.Name)
	}
	return out
}

// ---- collections: owner filtering ----

func TestCollectionsListForIsOwnerScoped(t *testing.T) {
	st := newTestStore(t)
	admin := mkUser(t, st, "admin", "admin")
	alice := mkUser(t, st, "alice", "user")
	bob := mkUser(t, st, "bob", "user")

	if _, err := st.Collections.Create("alice-col", ptr(alice.ID)); err != nil {
		t.Fatalf("create alice-col: %v", err)
	}
	if _, err := st.Collections.Create("bob-col", ptr(bob.ID)); err != nil {
		t.Fatalf("create bob-col: %v", err)
	}
	if _, err := st.Collections.Create("global-col", nil); err != nil {
		t.Fatalf("create global-col: %v", err)
	}

	aliceCols, err := st.Collections.ListFor(alice)
	if err != nil {
		t.Fatalf("ListFor(alice): %v", err)
	}
	sameSet(t, "ListFor(alice)", collectionNames(aliceCols), []string{"alice-col", "global-col"})

	bobCols, err := st.Collections.ListFor(bob)
	if err != nil {
		t.Fatalf("ListFor(bob): %v", err)
	}
	sameSet(t, "ListFor(bob)", collectionNames(bobCols), []string{"bob-col", "global-col"})

	adminCols, err := st.Collections.ListFor(admin)
	if err != nil {
		t.Fatalf("ListFor(admin): %v", err)
	}
	sameSet(t, "ListFor(admin)", collectionNames(adminCols),
		[]string{"alice-col", "bob-col", "global-col"})
}

func TestCollectionPermissions(t *testing.T) {
	st := newTestStore(t)
	admin := mkUser(t, st, "admin", "admin")
	alice := mkUser(t, st, "alice", "user")
	bob := mkUser(t, st, "bob", "user")

	aliceOwned := &models.Collection{ID: 1, Name: "alice-col", OwnerID: ptr(alice.ID)}
	global := &models.Collection{ID: 2, Name: "global-col"}

	cases := []struct {
		name      string
		u         models.User
		c         *models.Collection
		canView   bool
		canManage bool
	}{
		{"owner views own", alice, aliceOwned, true, true},
		{"other user cannot view", bob, aliceOwned, false, false},
		{"admin views any", admin, aliceOwned, true, true},
		{"global is viewable by all", bob, global, true, false},
		{"global is not manageable by users", alice, global, true, false},
		{"admin manages global", admin, global, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := st.Collections.CanView(tc.u, tc.c); got != tc.canView {
				t.Errorf("CanView = %v, want %v", got, tc.canView)
			}
			if got := st.Collections.CanManage(tc.u, tc.c); got != tc.canManage {
				t.Errorf("CanManage = %v, want %v", got, tc.canManage)
			}
		})
	}
}

func TestRequestPermissionsCombineCollectionAndOwner(t *testing.T) {
	st := newTestStore(t)
	admin := mkUser(t, st, "admin", "admin")
	alice := mkUser(t, st, "alice", "user")
	bob := mkUser(t, st, "bob", "user")

	alicePrivate := &models.Collection{ID: 1, Name: "alice-col", OwnerID: ptr(alice.ID)}
	globalCol := &models.Collection{ID: 2, Name: "global-col"}
	aliceReq := &models.Request{ID: 1, CollectionID: 1, OwnerID: ptr(alice.ID)}
	globalReq := &models.Request{ID: 2, CollectionID: 2}
	bobReqInGlobal := &models.Request{ID: 3, CollectionID: 2, OwnerID: ptr(bob.ID)}
	globalReqInPrivate := &models.Request{ID: 4, CollectionID: 1}

	cases := []struct {
		name      string
		u         models.User
		req       *models.Request
		col       *models.Collection
		canUse    bool
		canManage bool
	}{
		{"owner uses and manages own request", alice, aliceReq, alicePrivate, true, true},
		{"other user cannot use a private request", bob, aliceReq, alicePrivate, false, false},
		{"admin uses and manages any request", admin, aliceReq, alicePrivate, true, true},
		{"global request is usable by any user", alice, globalReq, globalCol, true, false},
		{"global request is usable but not manageable by users", alice, globalReq, globalCol, true, false},
		{"admin manages a global request", admin, globalReq, globalCol, true, true},
		{"another user's request is off limits in a shared collection", alice, bobReqInGlobal, globalCol, false, false},
		{"a global request in a private collection is off limits", bob, globalReqInPrivate, alicePrivate, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := st.CanUseRequest(tc.u, tc.req, tc.col); got != tc.canUse {
				t.Errorf("CanUseRequest = %v, want %v", got, tc.canUse)
			}
			if got := st.CanManageRequest(tc.u, tc.req, tc.col); got != tc.canManage {
				t.Errorf("CanManageRequest = %v, want %v", got, tc.canManage)
			}
		})
	}
}

// ---- requests / folders ----

func TestRequestCRUDRoundTrip(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	colID, err := st.Collections.Create("col", ptr(alice.ID))
	if err != nil {
		t.Fatalf("create collection: %v", err)
	}
	folderID, err := st.Folders.Create(colID, nil, "folder")
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}

	payload := RequestPayload{
		CollectionID: colID,
		FolderID:     ptr(folderID),
		Name:         "get-health",
		Method:       "GET",
		URL:          "http://10.0.0.1/health",
		Headers:      `{"X-Tenant":"acme"}`,
		Query:        `[{"k":"page","v":"1"}]`,
		BodyType:     "json",
		Body:         `{"a":1}`,
	}
	id, err := st.Requests.Create(payload, ptr(alice.ID))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	got, err := st.Requests.Get(id)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if got.Name != payload.Name || got.Method != payload.Method || got.URL != payload.URL {
		t.Errorf("request = %+v, want the stored payload", got)
	}
	if got.FolderID == nil || *got.FolderID != folderID {
		t.Errorf("FolderID = %v, want %d", got.FolderID, folderID)
	}
	if got.OwnerID == nil || *got.OwnerID != alice.ID {
		t.Errorf("OwnerID = %v, want %d", got.OwnerID, alice.ID)
	}
	if got.Headers != payload.Headers || got.Query != payload.Query || got.Body != payload.Body {
		t.Errorf("request = %+v, want headers/query/body preserved", got)
	}

	stored := RequestPayload{Headers: got.Headers, Query: got.Query}
	if h := stored.HeadersMap(); h["X-Tenant"] != "acme" {
		t.Errorf("HeadersMap = %v, want X-Tenant=acme", h)
	}
	if q := stored.QueryPairs(); len(q) != 1 || q[0] != [2]string{"page", "1"} {
		t.Errorf("QueryPairs = %v, want [[page 1]]", q)
	}

	// An empty body_type defaults to "none", and a nil owner stays global.
	plainID, err := st.Requests.Create(RequestPayload{
		CollectionID: colID, Name: "plain", Method: "POST", URL: "http://10.0.0.1/x",
	}, nil)
	if err != nil {
		t.Fatalf("create request without body_type: %v", err)
	}
	plain, err := st.Requests.Get(plainID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if plain.BodyType != "none" {
		t.Errorf("BodyType = %q, want none", plain.BodyType)
	}
	if plain.OwnerID != nil {
		t.Errorf("OwnerID = %v, want nil for a global request", plain.OwnerID)
	}

	payload.Name = "renamed"
	payload.Method = "PATCH"
	payload.URL = "http://10.0.0.1/renamed"
	if err := st.Requests.Update(id, payload); err != nil {
		t.Fatalf("update request: %v", err)
	}
	updated, err := st.Requests.Get(id)
	if err != nil {
		t.Fatalf("get updated request: %v", err)
	}
	if updated.Name != "renamed" || updated.Method != "PATCH" || updated.URL != payload.URL {
		t.Errorf("updated request = %+v, want the new name, method and url", updated)
	}

	list, err := st.Requests.List(colID)
	if err != nil {
		t.Fatalf("list requests: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d requests, want 2", len(list))
	}

	if err := st.Requests.Delete(id); err != nil {
		t.Fatalf("delete request: %v", err)
	}
	if _, err := st.Requests.Get(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestFoldersCascadeWhenCollectionIsDeleted(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	colID, err := st.Collections.Create("col", ptr(alice.ID))
	if err != nil {
		t.Fatalf("create collection: %v", err)
	}
	parent, err := st.Folders.Create(colID, nil, "parent")
	if err != nil {
		t.Fatalf("create parent folder: %v", err)
	}
	if _, err := st.Folders.Create(colID, ptr(parent), "child"); err != nil {
		t.Fatalf("create child folder: %v", err)
	}
	if _, err := st.Requests.Create(RequestPayload{
		CollectionID: colID, FolderID: ptr(parent), Name: "r", Method: "GET", URL: "http://10.0.0.1/",
	}, ptr(alice.ID)); err != nil {
		t.Fatalf("create request: %v", err)
	}

	folders, err := st.Folders.List(colID)
	if err != nil {
		t.Fatalf("list folders: %v", err)
	}
	if len(folders) != 2 {
		t.Fatalf("listed %d folders, want 2", len(folders))
	}
	var child *models.Folder
	for _, f := range folders {
		if f.Name == "child" {
			child = f
		}
	}
	if child == nil || child.ParentID == nil || *child.ParentID != parent {
		t.Errorf("child folder = %+v, want ParentID %d", child, parent)
	}

	if err := st.Collections.Delete(colID); err != nil {
		t.Fatalf("delete collection: %v", err)
	}
	if folders, err = st.Folders.List(colID); err != nil || len(folders) != 0 {
		t.Errorf("%d folders survived their collection (err %v)", len(folders), err)
	}
	if requests, err := st.Requests.List(colID); err != nil || len(requests) != 0 {
		t.Errorf("%d requests survived their collection (err %v)", len(requests), err)
	}
}

// ---- environments ----

func TestEnvironmentsAreScopedByUser(t *testing.T) {
	st := newTestStore(t)
	admin := mkUser(t, st, "admin", "admin")
	alice := mkUser(t, st, "alice", "user")
	bob := mkUser(t, st, "bob", "user")

	if _, err := st.Environments.Create("global-env", "global", nil, `{"host":"10.0.0.1"}`); err != nil {
		t.Fatalf("create global env: %v", err)
	}
	aliceEnvID, err := st.Environments.Create("alice-env", "user", ptr(alice.ID), `{"host":"10.0.0.2"}`)
	if err != nil {
		t.Fatalf("create alice env: %v", err)
	}
	if _, err := st.Environments.Create("bob-env", "user", ptr(bob.ID), `{"host":"10.0.0.3"}`); err != nil {
		t.Fatalf("create bob env: %v", err)
	}
	aliceEnv, err := st.Environments.Get(aliceEnvID)
	if err != nil {
		t.Fatalf("get alice env: %v", err)
	}
	if aliceEnv.Vars != `{"host":"10.0.0.2"}` {
		t.Errorf("vars = %q, want the stored JSON", aliceEnv.Vars)
	}

	aliceEnvs, err := st.Environments.ListFor(alice)
	if err != nil {
		t.Fatalf("ListFor(alice): %v", err)
	}
	sameSet(t, "ListFor(alice)", environmentNames(aliceEnvs), []string{"global-env", "alice-env"})

	bobEnvs, err := st.Environments.ListFor(bob)
	if err != nil {
		t.Fatalf("ListFor(bob): %v", err)
	}
	sameSet(t, "ListFor(bob)", environmentNames(bobEnvs), []string{"global-env", "bob-env"})

	adminEnvs, err := st.Environments.ListFor(admin)
	if err != nil {
		t.Fatalf("ListFor(admin): %v", err)
	}
	sameSet(t, "ListFor(admin)", environmentNames(adminEnvs),
		[]string{"global-env", "alice-env", "bob-env"})

	globalEnv := &models.Environment{ID: 99, Name: "global-env", Scope: "global"}
	if st.Environments.CanView(bob, aliceEnv) {
		t.Error("bob must not view alice's user-scoped environment")
	}
	if !st.Environments.CanView(bob, globalEnv) {
		t.Error("a global environment should be viewable by every user")
	}
	if st.Environments.CanManage(bob, globalEnv) {
		t.Error("users must not manage global environments")
	}
	if !st.Environments.CanManage(alice, aliceEnv) {
		t.Error("the owner must be able to manage their own environment")
	}
	if !st.Environments.CanManage(admin, aliceEnv) || !st.Environments.CanManage(admin, globalEnv) {
		t.Error("admins must be able to manage every environment")
	}

	// A user-scoped name may repeat across owners, but not for the same owner.
	if _, err := st.Environments.Create("alice-env", "user", ptr(bob.ID), `{}`); err != nil {
		t.Errorf("the same env name should be allowed for a different owner: %v", err)
	}
	if _, err := st.Environments.Create("alice-env", "user", ptr(alice.ID), `{}`); err == nil {
		t.Error("a duplicate (scope, owner, name) environment was accepted")
	}

	if err := st.Environments.Update(aliceEnvID, "renamed-env", `{"host":"10.0.0.9"}`); err != nil {
		t.Fatalf("update env: %v", err)
	}
	if e, err := st.Environments.Get(aliceEnvID); err != nil || e.Name != "renamed-env" {
		t.Errorf("env after Update = %+v (%v), want the new name", e, err)
	}
	if err := st.Environments.Delete(aliceEnvID); err != nil {
		t.Fatalf("delete env: %v", err)
	}
	if _, err := st.Environments.Get(aliceEnvID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// ---- history: per-user scoping ----

func TestHistoryIsScopedToItsUser(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")
	bob := mkUser(t, st, "bob", "user")

	aliceID, err := st.History.Insert(nil, alice.ID, "GET", "http://10.0.0.1/a", 200, 5, "req-a", "res-a")
	if err != nil {
		t.Fatalf("insert alice history: %v", err)
	}
	bobID, err := st.History.Insert(nil, bob.ID, "GET", "http://10.0.0.1/b", 500, 7, "req-b", "res-b")
	if err != nil {
		t.Fatalf("insert bob history: %v", err)
	}
	linked := int64(42)
	if _, err := st.History.Insert(&linked, alice.ID, "POST", "http://10.0.0.1/c", 201, 9, "req-c", "res-c"); err != nil {
		t.Fatalf("insert linked history: %v", err)
	}

	aliceItems, err := st.History.List(alice.ID, nil, 50)
	if err != nil {
		t.Fatalf("List(alice): %v", err)
	}
	if len(aliceItems) != 2 {
		t.Fatalf("alice sees %d history rows, want 2", len(aliceItems))
	}
	for _, it := range aliceItems {
		if it.UserID != alice.ID {
			t.Errorf("alice's history contains a row owned by user %d", it.UserID)
		}
		if it.CreatedAt.IsZero() {
			t.Error("history row has a zero created_at")
		}
	}

	filtered, err := st.History.List(alice.ID, &linked, 50)
	if err != nil {
		t.Fatalf("List(alice, request_id): %v", err)
	}
	if len(filtered) != 1 || filtered[0].RequestID == nil || *filtered[0].RequestID != linked {
		t.Fatalf("request_id filter returned %d rows, want the single linked row", len(filtered))
	}

	// Another user can neither read nor delete someone else's history.
	if _, err := st.History.Get(bobID, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("alice reading bob's history = %v, want ErrNotFound", err)
	}
	if err := st.History.Delete(bobID, alice.ID); err != nil {
		t.Fatalf("cross-user Delete returned an error: %v", err)
	}
	if _, err := st.History.Get(bobID, bob.ID); err != nil {
		t.Errorf("bob's history row was deleted by another user: %v", err)
	}

	bobItems, err := st.History.List(bob.ID, nil, 50)
	if err != nil {
		t.Fatalf("List(bob): %v", err)
	}
	if len(bobItems) != 1 || bobItems[0].ID != bobID {
		t.Fatalf("bob sees %d rows, want only his own", len(bobItems))
	}

	if err := st.History.Delete(aliceID, alice.ID); err != nil {
		t.Fatalf("delete own history: %v", err)
	}
	if _, err := st.History.Get(aliceID, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("history row still readable after Delete: %v", err)
	}
}

func TestHistoryListRespectsTheLimit(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	var last int64
	for i := 0; i < 5; i++ {
		id, err := st.History.Insert(nil, alice.ID, "GET", "http://10.0.0.1/x", 200, 1, "req", "res")
		if err != nil {
			t.Fatalf("insert history %d: %v", i, err)
		}
		last = id
	}

	items, err := st.History.List(alice.ID, nil, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("List(limit 2) returned %d rows", len(items))
	}
	if items[0].ID != last {
		t.Errorf("newest row id = %d, want %d (newest first)", items[0].ID, last)
	}
}

func TestHistoryPurgeKeepsTheNewestRows(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	var last int64
	for i := 0; i < 5; i++ {
		id, err := st.History.Insert(nil, alice.ID, "GET", "http://10.0.0.1/x", 200, 1, "req", "res")
		if err != nil {
			t.Fatalf("insert history %d: %v", i, err)
		}
		last = id
	}

	if err := st.History.Purge(2); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	items, err := st.History.List(alice.ID, nil, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("kept %d history rows, want 2", len(items))
	}
	if items[0].ID != last {
		t.Errorf("newest history row id = %d, want %d", items[0].ID, last)
	}

	// A non-positive cap is a no-op rather than "delete everything".
	if err := st.History.Purge(0); err != nil {
		t.Fatalf("Purge(0): %v", err)
	}
	if items, err = st.History.List(alice.ID, nil, 50); err != nil || len(items) != 2 {
		t.Fatalf("Purge(0) changed the row count: %d rows, err %v", len(items), err)
	}
}

// ---- secrets ----

func TestSecretsReturnCiphertextOnly(t *testing.T) {
	st := newTestStore(t)
	admin := mkUser(t, st, "admin", "admin")

	blob := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := st.Secrets.Create("api_key", blob, admin.ID); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := st.Secrets.Create("api_key", blob, admin.ID); err == nil {
		t.Error("a duplicate secret name was accepted")
	}
	if _, err := st.Secrets.Create("zeta", blob, admin.ID); err != nil {
		t.Fatalf("create second secret: %v", err)
	}

	got, ok, err := st.Secrets.GetByName("api_key")
	if err != nil || !ok {
		t.Fatalf("GetByName = (%v, %v, %v), want the stored blob", got, ok, err)
	}
	if string(got) != string(blob) {
		t.Errorf("GetByName blob = %v, want %v", got, blob)
	}

	metas, err := st.Secrets.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 2 || metas[0].Name != "api_key" || metas[1].Name != "zeta" {
		t.Fatalf("List = %+v, want both secrets ordered by name", metas)
	}
	if metas[0].UpdatedAt.IsZero() {
		t.Error("List returned a zero updated_at")
	}

	if _, ok, err := st.Secrets.GetByName("missing"); err != nil || ok {
		t.Errorf("GetByName(missing) = (_, %v, %v), want (false, nil)", ok, err)
	}
	if err := st.Secrets.Update("missing", blob); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update(missing) = %v, want ErrNotFound", err)
	}
	if err := st.Secrets.Update("api_key", []byte{0x09}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got, _, err = st.Secrets.GetByName("api_key"); err != nil || string(got) != string([]byte{0x09}) {
		t.Errorf("GetByName after Update = %v (%v), want the new blob", got, err)
	}

	if err := st.Secrets.Delete(metas[0].ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	remaining, err := st.Secrets.List()
	if err != nil || len(remaining) != 1 || remaining[0].Name != "zeta" {
		t.Errorf("after Delete List = %+v (%v), want only zeta", remaining, err)
	}
}

// ---- sessions ----

func TestSessionsLifecycle(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	if _, err := st.Sessions.Get("no-such-session"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(unknown) = %v, want ErrNotFound", err)
	}

	if err := st.Sessions.Create("live", alice.ID, 24*time.Hour); err != nil {
		t.Fatalf("create live session: %v", err)
	}
	if err := st.Sessions.Create("stale", alice.ID, -time.Hour); err != nil {
		t.Fatalf("create expired session: %v", err)
	}

	sess, err := st.Sessions.Get("live")
	if err != nil {
		t.Fatalf("get live session: %v", err)
	}
	if sess.UserID != alice.ID {
		t.Errorf("session user = %d, want %d", sess.UserID, alice.ID)
	}
	if !sess.ExpiresAt.After(time.Now()) {
		t.Errorf("live session expires at %v, which is already past", sess.ExpiresAt)
	}

	if err := st.Sessions.PurgeExpired(); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if _, err := st.Sessions.Get("stale"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session survived the purge: %v", err)
	}
	if _, err := st.Sessions.Get("live"); err != nil {
		t.Errorf("live session was purged: %v", err)
	}

	if err := st.Sessions.Delete("live"); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, err := st.Sessions.Get("live"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// ---- users ----

func TestUsersLifecycle(t *testing.T) {
	st := newTestStore(t)
	alice := mkUser(t, st, "alice", "user")

	if !alice.Enabled {
		t.Error("a new user should be enabled")
	}
	if alice.Role != "user" {
		t.Errorf("role = %q, want user", alice.Role)
	}
	if _, err := st.Users.Create("alice", "user", "s", "h"); err == nil {
		t.Error("a duplicate username was accepted")
	}
	if n, err := st.Users.Count(); err != nil || n != 1 {
		t.Errorf("Count = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := st.Users.GetByID(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID(999) = %v, want ErrNotFound", err)
	}
	if _, err := st.Users.GetByUsername("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByUsername(nobody) = %v, want ErrNotFound", err)
	}

	byName, err := st.Users.GetByUsername("alice")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if byName.ID != alice.ID {
		t.Errorf("GetByUsername id = %d, want %d", byName.ID, alice.ID)
	}

	if err := st.Users.SetPassword(alice.ID, "new-salt", "new-hash"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	after, err := st.Users.GetByID(alice.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if after.Salt != "new-salt" || after.PasswordHash != "new-hash" {
		t.Error("SetPassword did not persist the new credentials")
	}

	if err := st.Users.SetEnabled(alice.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if after, err = st.Users.GetByID(alice.ID); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if after.Enabled {
		t.Error("SetEnabled(false) did not disable the user")
	}

	if list, err := st.Users.List(); err != nil || len(list) != 1 {
		t.Errorf("List = (%d users, %v), want 1", len(list), err)
	}

	if err := st.Users.Delete(alice.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if n, _ := st.Users.Count(); n != 0 {
		t.Errorf("Count after Delete = %d, want 0", n)
	}
}

// ---- settings ----

func TestSettingsUpsertAndAuditCap(t *testing.T) {
	st := newTestStore(t)

	if v, ok, err := st.Settings.Get("missing"); err != nil || ok || v != "" {
		t.Fatalf("Get(missing) = (%q, %v, %v), want (\"\", false, nil)", v, ok, err)
	}
	if err := st.Settings.Set("ssrf_whitelist", "10.0.0.0/8"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := st.Settings.Set("ssrf_whitelist", "192.168.0.0/16"); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	v, ok, err := st.Settings.Get("ssrf_whitelist")
	if err != nil || !ok || v != "192.168.0.0/16" {
		t.Fatalf("Get after overwrite = (%q, %v, %v), want the new value", v, ok, err)
	}

	all, err := st.Settings.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if all["ssrf_whitelist"] != "192.168.0.0/16" {
		t.Errorf("All = %v, want the stored value", all)
	}

	// The audit trail keeps only the newest maxEntries lines.
	want := []string{"entry-c", "entry-d", "entry-e"}
	for _, entry := range []string{"entry-a", "entry-b", "entry-c", "entry-d", "entry-e"} {
		if err := st.Settings.AppendAudit(entry, 3); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	raw, _, err := st.Settings.Get("audit_log")
	if err != nil {
		t.Fatalf("Get(audit_log): %v", err)
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("audit_log is not valid JSON: %v", err)
	}
	sameSet(t, "audit log", entries, want)

	// A non-positive cap falls back to the default instead of dropping history.
	if err := st.Settings.AppendAudit("entry-f", 0); err != nil {
		t.Fatalf("AppendAudit(0): %v", err)
	}
	raw, _, err = st.Settings.Get("audit_log")
	if err != nil {
		t.Fatalf("Get(audit_log): %v", err)
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("audit_log is not valid JSON: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("audit log holds %d entries after a defaulted append, want 4", len(entries))
	}
}

// TestStoreQueriesMatchSchema catches SQL that drifts away from the schema:
// every repository query below must run against a freshly migrated database.
func TestStoreQueriesMatchSchema(t *testing.T) {
	st := newTestStore(t)
	user := models.User{ID: 1, Role: "user"}

	checks := []struct {
		name string
		fn   func() error
	}{
		{"users", func() error { _, err := st.Users.Count(); return err }},
		{"collections", func() error { _, err := st.Collections.ListFor(user); return err }},
		{"folders", func() error { _, err := st.Folders.List(1); return err }},
		{"requests", func() error { _, err := st.Requests.List(1); return err }},
		{"environments", func() error { _, err := st.Environments.ListFor(user); return err }},
		{"secrets", func() error { _, err := st.Secrets.List(); return err }},
		{"history", func() error { _, err := st.History.List(1, nil, 10); return err }},
		{"settings", func() error { _, err := st.Settings.All(); return err }},
		{"sessions", func() error { _, err := st.Sessions.Get("none"); return err }},
	}
	for _, c := range checks {
		if err := c.fn(); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: query failed: %v", c.name, err)
		}
	}
}
