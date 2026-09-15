package repository

import (
	"database/sql"

	"postlite/internal/models"
)

// Store bundles all entity repositories over a single SQLite handle.
type Store struct {
	Users        *Users
	Sessions     *Sessions
	Collections  *Collections
	Folders      *Folders
	Requests     *Requests
	Environments *Environments
	Secrets      *Secrets
	History      *History
	Settings     *Settings
}

func New(db *sql.DB) *Store {
	return &Store{
		Users:        NewUsers(db),
		Sessions:     NewSessions(db),
		Collections:  NewCollections(db),
		Folders:      NewFolders(db),
		Requests:     NewRequests(db),
		Environments: NewEnvironments(db),
		Secrets:      NewSecrets(db),
		History:      NewHistory(db),
		Settings:     NewSettings(db),
	}
}

// CanUseRequest reports whether u may execute/read req (with its collection).
func (s *Store) CanUseRequest(u models.User, req *models.Request, col *models.Collection) bool {
	if !s.Collections.CanView(u, col) {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	if req.OwnerID == nil {
		return true // global (admin-created) request is usable by everyone
	}
	return *req.OwnerID == u.ID
}

// CanManageRequest reports whether u may modify/delete req.
func (s *Store) CanManageRequest(u models.User, req *models.Request, col *models.Collection) bool {
	if u.Role == "admin" {
		return true
	}
	if !s.Collections.CanManage(u, col) {
		return false
	}
	return req.OwnerID != nil && *req.OwnerID == u.ID
}
