package httpapi

import (
	"net/http"
	"strconv"
)

func (s *Server) listHistory(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var reqID *int64
	if v := r.URL.Query().Get("request_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			reqID = &n
		}
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.Store.History.List(u.ID, reqID, limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, items)
}

func (s *Server) getHistory(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	item, err := s.Store.History.Get(id, u.ID)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "history item not found")
		return
	}
	ok(w, item)
}

func (s *Server) deleteHistory(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	if err := s.Store.History.Delete(id, u.ID); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{"deleted": id})
}
