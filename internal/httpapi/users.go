package httpapi

import (
	"net/http"

	"postlite/internal/auth"
)

type userCreateBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, okd := s.requireAdmin(w, r); !okd {
		return
	}
	users, err := s.Store.Users.List()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	var b userCreateBody
	if !decodeBody(w, r, &b) {
		return
	}
	if len(b.Username) < 3 || len(b.Username) > 32 {
		fail(w, http.StatusBadRequest, "bad_request", "username must be 3-32 characters")
		return
	}
	if len(b.Password) < 6 {
		fail(w, http.StatusBadRequest, "bad_request", "password must be at least 6 characters")
		return
	}
	role := b.Role
	if role == "" {
		role = "user"
	}
	if _, err := auth.EnsureRole(role); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "role must be admin or user")
		return
	}
	hash, salt, err := auth.HashPassword(b.Password)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	id, err := s.Store.Users.Create(b.Username, role, salt, hash)
	if err != nil {
		fail(w, http.StatusConflict, "conflict", "username already exists")
		return
	}
	s.audit(admin.Username, "user.create", "id="+itoa(id))
	okStatus(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	if id == admin.ID {
		fail(w, http.StatusBadRequest, "bad_request", "cannot delete your own account")
		return
	}
	if err := s.Store.Users.Delete(id); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(admin.Username, "user.delete", "id="+itoa(id))
	ok(w, map[string]any{"deleted": id})
}

func (s *Server) setUserEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	if id == admin.ID {
		fail(w, http.StatusBadRequest, "bad_request", "cannot disable your own account")
		return
	}
	if err := s.Store.Users.SetEnabled(id, enabled); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	action := "user.enable"
	if !enabled {
		action = "user.disable"
	}
	s.audit(admin.Username, action, "id="+itoa(id))
	ok(w, map[string]any{"id": id, "enabled": enabled})
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) { s.setUserEnabled(w, r, false) }
func (s *Server) enableUser(w http.ResponseWriter, r *http.Request)  { s.setUserEnabled(w, r, true) }

type resetPasswordBody struct {
	NewPassword string `json:"new_password"`
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	id, okid := idParam(w, r, "id")
	if !okid {
		return
	}
	var b resetPasswordBody
	_ = decodeBody(w, r, &b) // body optional: generates a random password
	newPass := b.NewPassword
	if newPass == "" {
		var err error
		newPass, err = auth.RandomPassword(16)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if len(newPass) < 6 {
		fail(w, http.StatusBadRequest, "bad_request", "password too short")
		return
	}
	hash, salt, err := auth.HashPassword(newPass)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.Store.Users.SetPassword(id, salt, hash); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(admin.Username, "user.reset_password", "id="+itoa(id))
	// The new password is shown to the admin exactly once.
	ok(w, map[string]any{"id": id, "password": newPass})
}
