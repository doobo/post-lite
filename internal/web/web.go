package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// zeroTime tells http.ServeContent the asset has no meaningful mtime.
var zeroTime time.Time

//go:embed all:static
var staticFS embed.FS

// Sub returns the static file system rooted at the embedded "static" dir.
func Sub() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}

// Handler serves the SPA: embedded assets are served with a content-hash ETag so
// a browser can never keep running the previous build's app.js, and anything
// else (client-side routes) falls back to index.html.
func Handler() http.Handler {
	sub, err := Sub()
	if err != nil {
		return http.NotFoundHandler()
	}
	assets := map[string][]byte{}
	etags := map[string]string{}
	_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := fs.ReadFile(sub, p)
		if rerr != nil {
			return nil
		}
		key := strings.TrimPrefix(path.Clean(p), "./")
		assets[key] = b
		sum := sha256.Sum256(b)
		etags[key] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})

	serve := func(w http.ResponseWriter, r *http.Request, key string) {
		body, ok := assets[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Embedded files carry no mtime, which leaves browsers free to cache them
		// heuristically. Revalidate on every load instead; the ETag makes that a
		// cheap 304, and an upgrade can't leave a stale app.js behind.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etags[key])
		http.ServeContent(w, r, key, zeroTime, bytes.NewReader(body))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		if key == "" {
			key = "index.html"
		}
		if _, ok := assets[key]; !ok {
			// SPA fallback: serve index.html for unknown non-file routes.
			key = "index.html"
			if _, ok := assets[key]; !ok {
				http.Error(w, "web UI not embedded", http.StatusNotFound)
				return
			}
		}
		serve(w, r, key)
	})
}
