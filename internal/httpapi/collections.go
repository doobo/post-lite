package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"postlite/internal/repository"
)

type collectionBody struct {
	Name   string `json:"name"`
	Global bool   `json:"global"`
}

func (s *Server) listCollections(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	cols, err := s.Store.Collections.ListFor(u)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, cols)
}

func (s *Server) createCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b collectionBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	var owner *int64
	if b.Global {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, "forbidden", "only admins can create global collections")
			return
		}
	} else {
		v := u.ID
		owner = &v
	}
	id, err := s.Store.Collections.Create(b.Name, owner)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if b.Global {
		s.audit(u.Username, "collection.create_global", "id="+itoa(id)+" name="+b.Name)
	}
	okStatus(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) getCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if errors.Is(err, repository.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "collection not found")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !s.Store.Collections.CanView(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this collection")
		return
	}
	folders, err := s.Store.Folders.List(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	requests, err := s.Store.Requests.List(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{"collection": c, "folders": folders, "requests": requests})
}

func (s *Server) updateCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "collection not found")
		return
	}
	if !s.Store.Collections.CanManage(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this collection")
		return
	}
	var b collectionBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if err := s.Store.Collections.UpdateName(id, b.Name); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{"id": id})
}

func (s *Server) deleteCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "collection not found")
		return
	}
	if !s.Store.Collections.CanManage(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this collection")
		return
	}
	if err := s.Store.Collections.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(u.Username, "collection.delete", "id="+itoa(id)+" name="+c.Name)
	ok(w, map[string]any{"deleted": id})
}

// ---- folders ----

type folderBody struct {
	Name     string `json:"name"`
	ParentID *int64 `json:"parent_id"`
}

func (s *Server) listFolders(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if err != nil || !s.Store.Collections.CanView(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this collection")
		return
	}
	folders, err := s.Store.Folders.List(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, folders)
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if err != nil || !s.Store.Collections.CanManage(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this collection")
		return
	}
	var b folderBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	fid, err := s.Store.Folders.Create(id, b.ParentID, b.Name)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	okStatus(w, http.StatusCreated, map[string]any{"id": fid})
}

// ---- export / import ----

type expFolder struct {
	ID       int64  `json:"id"`
	ParentID *int64 `json:"parent_id"`
	Name     string `json:"name"`
}

// expRequest is one request in a postlite/v1 export. use_proxy is deliberately
// absent: a proxy preference only means something on the instance that has the
// proxy configured, so importing a collection elsewhere must not carry it over.
type expRequest struct {
	ID        int64             `json:"id"`
	FolderID  *int64            `json:"folder_id"`
	Name      string            `json:"name"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Query     []kvPair          `json:"query"`
	BodyType  string            `json:"body_type"`
	Body      string            `json:"body"`
	Variables string            `json:"variables,omitempty"` // graphql only
}

type kvPair struct {
	K string `json:"k"`
	V string `json:"v"`
}

type expCollection struct {
	Name     string       `json:"name"`
	Format   string       `json:"format"`
	Folders  []expFolder  `json:"folders"`
	Requests []expRequest `json:"requests"`
}

func (s *Server) exportCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	c, err := s.Store.Collections.Get(id)
	if err != nil || !s.Store.Collections.CanView(u, c) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this collection")
		return
	}
	folders, err := s.Store.Folders.List(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	requests, err := s.Store.Requests.List(id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := expCollection{
		Name:   c.Name,
		Format: "postlite/v1",
	}
	for _, f := range folders {
		out.Folders = append(out.Folders, expFolder{ID: f.ID, ParentID: f.ParentID, Name: f.Name})
	}
	for _, rq := range requests {
		er := expRequest{
			ID: rq.ID, FolderID: rq.FolderID, Name: rq.Name, Method: rq.Method,
			URL: rq.URL, BodyType: rq.BodyType, Body: rq.Body, Variables: rq.Variables,
		}
		if rq.Headers != "" {
			_ = json.Unmarshal([]byte(rq.Headers), &er.Headers)
		}
		for _, p := range parseQuery(rq.Query) {
			er.Query = append(er.Query, kvPair{K: p[0], V: p[1]})
		}
		out.Requests = append(out.Requests, er)
	}
	payload, _ := json.MarshalIndent(out, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="collection-`+itoa(id)+`.json"`)
	_, _ = w.Write(payload)
}

type importBody struct {
	JSON   string `json:"json"`
	Global bool   `json:"global"`
}

func (s *Server) importCollection(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b importBody
	if !decodeBody(w, r, &b) {
		return
	}
	var exp expCollection
	if err := json.Unmarshal([]byte(b.JSON), &exp); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid collection JSON: "+err.Error())
		return
	}
	if exp.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "collection name is required")
		return
	}
	var owner *int64
	if b.Global {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, "forbidden", "only admins can import global collections")
			return
		}
	} else {
		v := u.ID
		owner = &v
	}
	colID, err := s.Store.Collections.Create(exp.Name, owner)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	oldToNew := map[int64]int64{}
	for _, f := range exp.Folders {
		var parent *int64
		if f.ParentID != nil {
			if np, found := oldToNew[*f.ParentID]; found {
				v := np
				parent = &v
			}
		}
		nid, err := s.Store.Folders.Create(colID, parent, f.Name)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		oldToNew[f.ID] = nid
	}
	for _, rq := range exp.Requests {
		_, err := s.Store.Requests.Create(repositoryRequestPayload(rq, colID, oldToNew), owner)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	s.audit(u.Username, "collection.import", "id="+itoa(colID)+" name="+exp.Name)
	okStatus(w, http.StatusCreated, map[string]any{"id": colID})
}

// repositoryRequestPayload adapts an exported request into the create payload.
func repositoryRequestPayload(rq expRequest, colID int64, oldToNew map[int64]int64) repository.RequestPayload {
	var p repository.RequestPayload
	p.CollectionID = colID
	p.Name = rq.Name
	p.Method = rq.Method
	p.URL = rq.URL
	p.BodyType = rq.BodyType
	p.Body = rq.Body
	p.Variables = rq.Variables
	if rq.Headers != nil {
		b, _ := json.Marshal(rq.Headers)
		p.Headers = string(b)
	}
	if rq.Query != nil {
		b, _ := json.Marshal(rq.Query)
		p.Query = string(b)
	}
	if rq.FolderID != nil {
		if np, found := oldToNew[*rq.FolderID]; found {
			p.FolderID = &np
		}
	}
	return p
}

// parseQuery decodes the stored query JSON ([{"k":"..","v":".."}]) into pairs.
func parseQuery(q string) [][2]string {
	var arr []kvPair
	if q != "" {
		_ = json.Unmarshal([]byte(q), &arr)
	}
	out := make([][2]string, 0, len(arr))
	for _, p := range arr {
		out = append(out, [2]string{p.K, p.V})
	}
	return out
}
