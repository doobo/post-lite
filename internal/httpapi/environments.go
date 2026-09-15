package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"postlite/internal/models"
	"postlite/internal/repository"
)

type envBody struct {
	Name    string            `json:"name"`
	Scope   string            `json:"scope"`
	OwnerID *int64            `json:"owner_id"`
	Vars    map[string]string `json:"vars"`
}

func parseVarsJSON(s string) map[string]string {
	m := map[string]string{}
	if s != "" {
		_ = json.Unmarshal([]byte(s), &m)
	}
	return m
}

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	envs, err := s.Store.Environments.ListFor(u)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	type envView struct {
		models.Environment
		VarsMap map[string]string `json:"vars_map"`
	}
	out := make([]envView, 0, len(envs))
	for _, e := range envs {
		out = append(out, envView{Environment: *e, VarsMap: parseVarsJSON(e.Vars)})
	}
	ok(w, out)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b envBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Name == "" {
		fail(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	scope := b.Scope
	if scope == "" {
		scope = "user"
	}
	if scope != "global" && scope != "user" {
		fail(w, http.StatusBadRequest, "bad_request", "scope must be global or user")
		return
	}
	var owner *int64
	if scope == "global" {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, "forbidden", "only admins can create global environments")
			return
		}
		owner = nil
	} else {
		if b.OwnerID != nil {
			if u.Role != "admin" {
				fail(w, http.StatusForbidden, "forbidden", "only admins can set owner_id")
				return
			}
			owner = b.OwnerID
		} else {
			v := u.ID
			owner = &v
		}
	}
	varsJSON, _ := json.Marshal(b.Vars)
	if b.Vars == nil {
		varsJSON = []byte("{}")
	}
	id, err := s.Store.Environments.Create(b.Name, scope, owner, string(varsJSON))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if scope == "global" {
		s.audit(u.Username, "env.create_global", "id="+itoa(id)+" name="+b.Name)
	}
	okStatus(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	e, err := s.Store.Environments.Get(id)
	if errors.Is(err, repository.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "environment not found")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !s.Store.Environments.CanView(u, e) {
		fail(w, http.StatusForbidden, "forbidden", "cannot access this environment")
		return
	}
	ok(w, map[string]any{"environment": e, "vars": parseVarsJSON(e.Vars)})
}

func (s *Server) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	e, err := s.Store.Environments.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "environment not found")
		return
	}
	if !s.Store.Environments.CanManage(u, e) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this environment")
		return
	}
	var b envBody
	if !decodeBody(w, r, &b) {
		return
	}
	name := b.Name
	if name == "" {
		name = e.Name
	}
	varsJSON, _ := json.Marshal(b.Vars)
	if b.Vars == nil {
		varsJSON = []byte("{}")
	}
	if err := s.Store.Environments.Update(id, name, string(varsJSON)); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{"id": id})
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	e, err := s.Store.Environments.Get(id)
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "environment not found")
		return
	}
	if !s.Store.Environments.CanManage(u, e) {
		fail(w, http.StatusForbidden, "forbidden", "cannot manage this environment")
		return
	}
	if err := s.Store.Environments.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(u.Username, "env.delete", "id="+itoa(id)+" name="+e.Name)
	ok(w, map[string]any{"deleted": id})
}

type activateBody struct {
	GlobalEnvID *int64 `json:"global_env_id"`
	UserEnvID   *int64 `json:"user_env_id"`
}

// activateEnvironment stores the selected env ids in settings:
//
//	"active_global_env" = <id>        (admin only)
//	"active_env_user_<uid>" = <id>    (owner, or admin for any user)
func (s *Server) activateEnvironment(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b activateBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.GlobalEnvID != nil {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, "forbidden", "only admins can activate the global environment")
			return
		}
		e, err := s.Store.Environments.Get(*b.GlobalEnvID)
		if err != nil || e.Scope != "global" {
			fail(w, http.StatusBadRequest, "bad_request", "global_env_id must reference a global environment")
			return
		}
		if err := s.Store.Settings.Set("active_global_env", strconv.FormatInt(*b.GlobalEnvID, 10)); err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		s.audit(u.Username, "env.activate_global", "id="+itoa(*b.GlobalEnvID)+" name="+e.Name)
	}
	if b.UserEnvID != nil {
		e, err := s.Store.Environments.Get(*b.UserEnvID)
		if err != nil || e.Scope != "user" {
			fail(w, http.StatusBadRequest, "bad_request", "user_env_id must reference a user environment")
			return
		}
		if e.OwnerID == nil || (*e.OwnerID != u.ID && u.Role != "admin") {
			fail(w, http.StatusForbidden, "forbidden", "cannot activate an environment you do not own")
			return
		}
		key := "active_env_user_" + strconv.FormatInt(u.ID, 10)
		if err := s.Store.Settings.Set(key, strconv.FormatInt(*b.UserEnvID, 10)); err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	ok(w, map[string]any{"activated": true})
}

// activeEnvIDs returns the currently active global + user env ids for u.
func (s *Server) activeEnvIDs(u models.User) (globalID, userEnvID *int64) {
	if v, found, _ := s.Store.Settings.Get("active_global_env"); found {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			globalID = &n
		}
	}
	if v, found, _ := s.Store.Settings.Get("active_env_user_" + strconv.FormatInt(u.ID, 10)); found {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			userEnvID = &n
		}
	}
	return
}
