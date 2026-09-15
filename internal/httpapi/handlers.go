package httpapi

import "net/http"

// Exported route handlers (thin wrappers over the unexported implementations).

func (s *Server) Login(w http.ResponseWriter, r *http.Request)    { s.login(w, r) }
func (s *Server) LoginKey(w http.ResponseWriter, r *http.Request) { s.loginKey(w, r) }
func (s *Server) Logout(w http.ResponseWriter, r *http.Request)   { s.logout(w, r) }
func (s *Server) Me(w http.ResponseWriter, r *http.Request)       { s.me(w, r) }

func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request)         { s.listUsers(w, r) }
func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request)        { s.createUser(w, r) }
func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request)        { s.deleteUser(w, r) }
func (s *Server) DisableUser(w http.ResponseWriter, r *http.Request)       { s.disableUser(w, r) }
func (s *Server) EnableUser(w http.ResponseWriter, r *http.Request)        { s.enableUser(w, r) }
func (s *Server) ResetUserPassword(w http.ResponseWriter, r *http.Request) { s.resetUserPassword(w, r) }

func (s *Server) ListCollections(w http.ResponseWriter, r *http.Request)  { s.listCollections(w, r) }
func (s *Server) CreateCollection(w http.ResponseWriter, r *http.Request) { s.createCollection(w, r) }
func (s *Server) GetCollection(w http.ResponseWriter, r *http.Request)    { s.getCollection(w, r) }
func (s *Server) UpdateCollection(w http.ResponseWriter, r *http.Request) { s.updateCollection(w, r) }
func (s *Server) DeleteCollection(w http.ResponseWriter, r *http.Request) { s.deleteCollection(w, r) }
func (s *Server) ExportCollection(w http.ResponseWriter, r *http.Request) { s.exportCollection(w, r) }
func (s *Server) ImportCollection(w http.ResponseWriter, r *http.Request) { s.importCollection(w, r) }
func (s *Server) ListFolders(w http.ResponseWriter, r *http.Request)      { s.listFolders(w, r) }
func (s *Server) CreateFolder(w http.ResponseWriter, r *http.Request)     { s.createFolder(w, r) }

func (s *Server) ListRequests(w http.ResponseWriter, r *http.Request)  { s.listRequests(w, r) }
func (s *Server) CreateRequest(w http.ResponseWriter, r *http.Request) { s.createRequest(w, r) }
func (s *Server) GetRequest(w http.ResponseWriter, r *http.Request)    { s.getRequest(w, r) }
func (s *Server) UpdateRequest(w http.ResponseWriter, r *http.Request) { s.updateRequest(w, r) }
func (s *Server) DeleteRequest(w http.ResponseWriter, r *http.Request) { s.deleteRequest(w, r) }

func (s *Server) ListEnvironments(w http.ResponseWriter, r *http.Request)  { s.listEnvironments(w, r) }
func (s *Server) CreateEnvironment(w http.ResponseWriter, r *http.Request) { s.createEnvironment(w, r) }
func (s *Server) GetEnvironment(w http.ResponseWriter, r *http.Request)    { s.getEnvironment(w, r) }
func (s *Server) UpdateEnvironment(w http.ResponseWriter, r *http.Request) { s.updateEnvironment(w, r) }
func (s *Server) DeleteEnvironment(w http.ResponseWriter, r *http.Request) { s.deleteEnvironment(w, r) }
func (s *Server) ActivateEnvironment(w http.ResponseWriter, r *http.Request) {
	s.activateEnvironment(w, r)
}

func (s *Server) CreateSecret(w http.ResponseWriter, r *http.Request) { s.createSecret(w, r) }
func (s *Server) UpdateSecret(w http.ResponseWriter, r *http.Request) { s.updateSecret(w, r) }
func (s *Server) ListSecrets(w http.ResponseWriter, r *http.Request)  { s.listSecrets(w, r) }
func (s *Server) DeleteSecret(w http.ResponseWriter, r *http.Request) { s.deleteSecret(w, r) }

func (s *Server) Execute(w http.ResponseWriter, r *http.Request)       { s.execute(w, r) }
func (s *Server) ListHistory(w http.ResponseWriter, r *http.Request)   { s.listHistory(w, r) }
func (s *Server) GetHistory(w http.ResponseWriter, r *http.Request)    { s.getHistory(w, r) }
func (s *Server) DeleteHistory(w http.ResponseWriter, r *http.Request) { s.deleteHistory(w, r) }

func (s *Server) GetSettings(w http.ResponseWriter, r *http.Request) { s.getSettings(w, r) }
func (s *Server) PutSettings(w http.ResponseWriter, r *http.Request) { s.putSettings(w, r) }
