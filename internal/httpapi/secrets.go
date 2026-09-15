package httpapi

import (
	"net/http"
	"regexp"
)

var secretNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)

type secretBody struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// createSecret (admin): encrypts the value and stores ciphertext only.
// The response never echoes the value.
func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	var b secretBody
	if !decodeBody(w, r, &b) {
		return
	}
	if !secretNameRe.MatchString(b.Name) {
		fail(w, http.StatusBadRequest, "bad_request", "name must match ^[a-zA-Z][a-zA-Z0-9._-]*$")
		return
	}
	if b.Value == "" {
		fail(w, http.StatusBadRequest, "bad_request", "value is required")
		return
	}
	if _, exists, _ := s.Store.Secrets.GetByName(b.Name); exists {
		fail(w, http.StatusConflict, "conflict", "secret already exists, use PUT to overwrite")
		return
	}
	blob := s.Vault.Seal(b.Value)
	id, err := s.Store.Secrets.Create(b.Name, blob, admin.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.Vault.Invalidate()
	s.audit(admin.Username, "secret.create", "id="+itoa(id)+" name="+b.Name)
	okStatus(w, http.StatusCreated, map[string]any{"id": id, "name": b.Name})
}

// updateSecret (admin): overwrites an existing secret.
func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	name := r.PathValue("name")
	if !secretNameRe.MatchString(name) {
		fail(w, http.StatusBadRequest, "bad_request", "invalid secret name")
		return
	}
	var b struct {
		Value string `json:"value"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Value == "" {
		fail(w, http.StatusBadRequest, "bad_request", "value is required")
		return
	}
	blob := s.Vault.Seal(b.Value)
	if err := s.Store.Secrets.Update(name, blob); err != nil {
		fail(w, http.StatusNotFound, "not_found", "secret not found")
		return
	}
	s.Vault.Invalidate()
	s.audit(admin.Username, "secret.update", "name="+name)
	ok(w, map[string]any{"name": name})
}

// listSecrets (admin): metadata only, never values.
func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	if _, okd := s.requireAdmin(w, r); !okd {
		return
	}
	metas, err := s.Store.Secrets.List()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, metas)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	if err := s.Store.Secrets.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.Vault.Invalidate()
	s.audit(admin.Username, "secret.delete", "id="+itoa(id))
	ok(w, map[string]any{"deleted": id})
}
