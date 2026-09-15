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
	if _, okm := validMethods[p.Method]; !okm {
		fail(w, http.StatusBadRequest, "bad_request", "method must be one of GET/POST/PUT/PATCH/DELETE")
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

func (s *Server) deleteRequest(w http.ResponseWriter, r *http.Request) {
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
	if err := s.Store.Requests.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(u.Username, "request.delete", "id="+itoa(id))
	ok(w, map[string]any{"deleted": id})
}
