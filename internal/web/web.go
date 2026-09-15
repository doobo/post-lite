package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var staticFS embed.FS

// Sub returns the static file system rooted at the embedded "static" dir.
func Sub() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}

// Handler serves the SPA: known static files are served, anything else
// (client-side routes) falls back to index.html.
func Handler() http.Handler {
	sub, err := Sub()
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := sub.Open(path); err != nil {
			// SPA fallback: serve index.html for unknown non-file routes.
			data, derr := fs.ReadFile(sub, "index.html")
			if derr != nil {
				http.Error(w, "web UI not embedded", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
