package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"postlite/internal/models"
	"postlite/internal/repository"
)

var validMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
}

// validBodyTypes is what the executor knows how to send: `none` (no body),
// `json` / `raw` (sent as typed) and `graphql` (query + variables composed into
// a GraphQL envelope at send time). An empty value means "none".
var validBodyTypes = map[string]struct{}{
	"none": {}, "json": {}, "raw": {}, "graphql": {},
}

// validProtocols is the realtime discriminator: http is the original sync
// executor, ws/sse are server-relayed realtime (see DESIGN V0.2). Empty means
// http for old clients. socketio/mqtt will extend this map later.
var validProtocols = map[string]struct{}{
	"http": {}, "ws": {}, "sse": {},
}

func checkProtocol(w http.ResponseWriter, protocol string) (string, bool) {
	if protocol == "" {
		return "http", true
	}
	if _, ok := validProtocols[protocol]; !ok {
		fail(w, http.StatusBadRequest, "bad_request", "protocol must be one of http/ws/sse")
		return "", false
	}
	return protocol, true
}

// maxScriptBytes bounds a pre-request script. The 4MB body limit already caps
// what can be stored; this is a much smaller bound so a saved script stays
// something a human could have written and stays cheap to compile on send.
const maxScriptBytes = 64 << 10

// checkScripts validates the pre-request and post-response script fields.
// Realtime rows are refused outright rather than storing scripts that would
// silently never run: the ws/sse path opens a relay session, not a script
// pipeline.
func checkScripts(w http.ResponseWriter, p repository.RequestPayload, protocol string) bool {
	for _, s := range []struct{ field, src string }{{"script", p.Script}, {"test_script", p.TestScript}} {
		if s.src == "" {
			continue
		}
		if len(s.src) > maxScriptBytes {
			fail(w, http.StatusBadRequest, "bad_request", s.field+" is too long (limit 64KB)")
			return false
		}
		if protocol != "http" {
			fail(w, http.StatusBadRequest, "bad_request", "scripts are only supported for http requests")
			return false
		}
	}
	return true
}

func checkBodyType(w http.ResponseWriter, bodyType string) bool {
	if bodyType == "" {
		return true
	}
	if _, ok := validBodyTypes[bodyType]; !ok {
		fail(w, http.StatusBadRequest, "bad_request", "body_type must be one of none/json/raw/graphql")
		return false
	}
	return true
}

func (s *Server) listRequests(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	cidStr := r.URL.Query().Get("collection_id")
	if cidStr == "" {
		fail(w, http.StatusBadRequest, "bad_request", "collection_id query parameter required")
		return
	}
	cid, err := strconv.ParseInt(cidStr, 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid collection_id")
		return
	}
	c, err := s.Store.Collections.Get(cid)
	if err != nil || !s.Store.Collections.CanView(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this collection")
		return
	}
	requests, err := s.Store.Requests.List(cid)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]*models.Request, 0, len(requests))
	for _, rq := range requests {
		if s.Store.CanUseRequest(u, rq, c) {
			out = append(out, rq)
		}
	}
	ok(w, out)
}

func (s *Server) createRequest(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var p repository.RequestPayload
	if !decodeBody(w, r, &p) {
		return
	}
	proto, okp := checkProtocol(w, p.Protocol)
	if !okp {
		return
	}
	p.Protocol = proto
	if _, okm := validMethods[p.Method]; !okm {
		fail(w, http.StatusBadRequest, "bad_request", "method must be one of GET/POST/PUT/PATCH/DELETE")
		return
	}
	// Realtime rows reuse method=GET so the V1 method CHECK keeps holding;
	// the wire scheme (ws/wss/http) lives in url.
	if (proto == "ws" || proto == "sse") && p.Method != "GET" {
		fail(w, http.StatusBadRequest, "bad_request", "ws/sse requests must use method GET")
		return
	}
	if p.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if p.URL == "" {
		fail(w, http.StatusBadRequest, "bad_request", "url is required")
		return
	}
	if !checkBodyType(w, p.BodyType) {
		return
	}
	if !checkScripts(w, p, proto) {
		return
	}

	if p.CollectionID == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "collection_id is required")
		return
	}
	c, err := s.Store.Collections.Get(p.CollectionID)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "collection not found")
		return
	}
	if !s.Store.Collections.CanView(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this collection")
		return
	}
	var owner *int64
	if u.Role == "admin" {
		owner = nil // admin creates global requests
	} else {
		v := u.ID
		owner = &v
	}
	id, err := s.Store.Requests.Create(p, owner)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	okStatus(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) getRequest(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	rq, err := s.Store.Requests.Get(id)
	if errors.Is(err, repository.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "request not found")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	c, err := s.Store.Collections.Get(rq.CollectionID)
	if err != nil || !s.Store.CanUseRequest(u, rq, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this request")
		return
	}
	ok(w, rq)
}

func (s *Server) updateRequest(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	rq, err := s.Store.Requests.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "request not found")
		return
	}
	c, err := s.Store.Collections.Get(rq.CollectionID)
	if err != nil || !s.Store.CanManageRequest(u, rq, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this request")
		return
	}
	var p repository.RequestPayload
	if !decodeBody(w, r, &p) {
		return
	}
	if p.Name == "" {
		p.Name = rq.Name
	}
	if _, okm := validMethods[p.Method]; !okm {
		fail(w, http.StatusBadRequest, "bad_request", "method must be one of GET/POST/PUT/PATCH/DELETE")
		return
	}
	proto, okp := checkProtocol(w, p.Protocol)
	if !okp {
		return
	}
	p.Protocol = proto
	if (proto == "ws" || proto == "sse") && p.Method != "GET" {
		fail(w, http.StatusBadRequest, "bad_request", "ws/sse requests must use method GET")
		return
	}
	if !checkBodyType(w, p.BodyType) {
		return
	}
	if !checkScripts(w, p, proto) {
		return
	}
	p.CollectionID = rq.CollectionID
	p.FolderID = rq.FolderID
	if p.URL == "" {
		p.URL = rq.URL
	}
	if err := s.Store.Requests.Update(id, p); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{"id": id})
}

// deleteRequest is admin-only, unlike the other request writes: an ordinary user
// can edit and save the requests they can see, but only an admin can remove one
// (a deleted request also strands its history rows). The UI hides the button for
// non-admins; this check is what actually enforces it.
func (s *Server) deleteRequest(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	if _, err := s.Store.Requests.Get(id); err != nil {
		fail(w, http.StatusNotFound, "not_found", "request not found")
		return
	}
	if err := s.Store.Requests.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(admin.Username, "request.delete", "id="+itoa(id))
	ok(w, map[string]any{"deleted": id})
}
