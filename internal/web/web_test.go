package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func assets(t *testing.T) fs.FS {
	t.Helper()
	sub, err := Sub()
	if err != nil {
		t.Fatalf("Sub: %v", err)
	}
	return sub
}

func readAsset(t *testing.T, f fs.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(f, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestBrandIsPostLite pins the product name in the shipped shell. The assets
// are embedded, so a partial rename is easy to miss until it is in a build.
func TestBrandIsPostLite(t *testing.T) {
	f := assets(t)

	html := readAsset(t, f, "index.html")
	if !strings.Contains(html, "<title>PostLite</title>") {
		t.Error("index.html must title the page PostLite")
	}
	for _, name := range []string{"index.html", "app.js"} {
		if !strings.Contains(readAsset(t, f, name), "PostLite") {
			t.Errorf("%s does not mention the product name PostLite", name)
		}
	}
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		if strings.Contains(readAsset(t, f, name), "APIBox") {
			t.Errorf("%s still mentions the old product name APIBox", name)
		}
	}
}

func TestShellAssetsAreEmbedded(t *testing.T) {
	f := assets(t)
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		if strings.TrimSpace(readAsset(t, f, name)) == "" {
			t.Errorf("%s is embedded but empty", name)
		}
	}
}

// TestHiddenAttributeIsAuthoritative guards the login flow. index.html toggles
// #login-view / #app-view by setting the hidden property, but the UA
// stylesheet's [hidden] { display: none } loses to any author display rule --
// and .login-wrap sets display:flex. Without this override the login card stays
// on screen after a successful sign-in, which looks exactly like "the Sign in
// button does nothing".
func TestHiddenAttributeIsAuthoritative(t *testing.T) {
	css := readAsset(t, assets(t), "app.css")

	if !regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`).MatchString(css) {
		t.Fatal("app.css must contain `[hidden] { display: none !important; }`, " +
			"otherwise author display rules keep hidden elements visible")
	}

	// The hazard the override exists for: an author display rule on an element
	// that is toggled via the hidden property.
	if !regexp.MustCompile(`\.login-wrap\s*\{[^}]*display:\s*flex`).MatchString(css) {
		t.Log(".login-wrap no longer sets display; re-check whether the [hidden] override is still needed")
	}
}

func TestIndexReferencesOnlyEmbeddedAssets(t *testing.T) {
	f := assets(t)
	html := readAsset(t, f, "index.html")

	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(html, -1)
	if len(refs) == 0 {
		t.Fatal("index.html references no assets at all")
	}
	for _, m := range refs {
		ref := m[1]
		if strings.HasPrefix(ref, "http") || strings.HasPrefix(ref, "//") || strings.HasPrefix(ref, "#") {
			t.Errorf("index.html references the external resource %q; the UI must be self-contained", ref)
			continue
		}
		name := strings.TrimPrefix(ref, "/")
		if _, err := f.Open(name); err != nil {
			t.Errorf("index.html references %q, which is not embedded: %v", ref, err)
		}
	}
}

// TestLoginIsEncrypted checks the browser half of the login handshake. The
// password must never be posted as a plain-text field, and the pure-JS fallback
// has to ship with the shell for the plain-HTTP case, where crypto.subtle does
// not exist (see internal/auth/loginenc.go for the server half).
func TestLoginIsEncrypted(t *testing.T) {
	f := assets(t)
	html := readAsset(t, f, "index.html")
	js := readAsset(t, f, "app.js")
	fallback := readAsset(t, f, "loginenc.js")

	if !strings.Contains(html, `src="/loginenc.js"`) {
		t.Error("index.html must load /loginenc.js, or logins break over plain HTTP")
	}
	if strings.Index(html, "/loginenc.js") > strings.Index(html, `src="/app.js"`) {
		t.Error("loginenc.js must be loaded before app.js")
	}
	if !strings.Contains(js, "'/auth/login-key'") || !strings.Contains(js, "window.LoginEnc") {
		t.Error("app.js must fetch the login key and fall back to window.LoginEnc")
	}
	if !strings.Contains(js, "encryptPassword($('#login-pass').value)") {
		t.Error("the login form must encrypt #login-pass before submitting")
	}
	if strings.Contains(js, "password: $('#login-pass').value") {
		t.Error("app.js still sends the login password in clear text")
	}
	if !strings.Contains(fallback, "function encrypt(") || !strings.Contains(fallback, "getRandomValues") {
		t.Error("loginenc.js must implement encrypt() on top of crypto.getRandomValues")
	}
}

// TestThemePickerIsWired pins the appearance switcher: the palettes live in
// app.css, the picker in the shell, and app.js is what connects the two (a
// missing option or palette silently leaves a theme unreachable).
func TestThemePickerIsWired(t *testing.T) {
	f := assets(t)
	html := readAsset(t, f, "index.html")
	js := readAsset(t, f, "app.js")
	css := readAsset(t, f, "app.css")

	if !strings.Contains(html, `id="theme-select"`) {
		t.Error("index.html has no #theme-select for app.js to bind to")
	}
	for _, theme := range []string{"light", "dark", "black"} {
		if !strings.Contains(html, `value="`+theme+`"`) {
			t.Errorf("index.html offers no %q option", theme)
		}
		// "dark" is the :root palette, the other two need their own block.
		if theme != "dark" && !strings.Contains(css, `html[data-theme="`+theme+`"]`) {
			t.Errorf("app.css has no palette for %q", theme)
		}
	}
	if !strings.Contains(js, "postlite.theme") || !strings.Contains(js, "documentElement.dataset.theme") {
		t.Error("app.js must apply the theme to <html> and remember the choice")
	}
}

// TestGraphQLBodyPanelIsWired pins the graphql half of the Body tab: the type
// option, the variables box that save/send must collect, and the handler that
// swaps the hint (a missing piece silently sends the query with no variables).
func TestGraphQLBodyPanelIsWired(t *testing.T) {
	js := readAsset(t, assets(t), "app.js")

	if !strings.Contains(js, "'none', 'json', 'raw', 'graphql'") {
		t.Error("the body type selector must offer graphql")
	}
	if !strings.Contains(js, `id="req-gql-vars"`) || !strings.Contains(js, `id="req-body-hint"`) {
		t.Error("the editor must render the graphql variables box and the hint slot")
	}
	if strings.Count(js, "req-gql-vars") < 2 {
		t.Error("the graphql variables box must be rendered and read back")
	}
	if !strings.Contains(js, "onBodyTypeChange()") {
		t.Error("changing the body type must call onBodyTypeChange()")
	}
	if !strings.Contains(js, "variables: ad.variables") || !strings.Contains(js, "variables: rq.variables") {
		t.Error("the variables document must survive save and reload")
	}
}

// TestDeleteRequestIsAdminGatedInTheUI checks the editor half of the admin-only
// delete: the button must be rendered from the role (content rendered after
// startApp() never receives the CSS/JS .admin-only pass), it must confirm first,
// and it must call the endpoint the server guards with requireAdmin.
func TestDeleteRequestIsAdminGatedInTheUI(t *testing.T) {
	js := readAsset(t, assets(t), "app.js")

	if !strings.Contains(js, "c.id && state.user && state.user.role === 'admin'") {
		t.Error("the request delete button must be gated on the admin role at render time")
	}
	if !strings.Contains(js, `id="btn-del-req"`) {
		t.Error("the request editor has no #btn-del-req button")
	}
	if !strings.Contains(js, "askConfirm('Delete request'") {
		t.Error("deleting a request must go through the in-page confirm dialog")
	}
	if !strings.Contains(js, "api('/requests/' + c.id, { method: 'DELETE' })") {
		t.Error("deleteRequest must call DELETE /api/requests/{id}")
	}
}

// TestLoginShellIdsExist checks the elements the wiring code binds to. A
// renamed id silently leaves the UI dead: no listener is attached and the
// browser falls back to a plain form submit.
func TestLoginShellIdsExist(t *testing.T) {
	f := assets(t)
	html := readAsset(t, f, "index.html")
	js := readAsset(t, f, "app.js")

	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		ids[m[1]] = true
	}
	for _, id := range []string{
		"login-view", "login-form", "login-user", "login-pass", "login-err",
		"app-view", "who", "flash", "btn-logout", "main-nav", "tree", "content",
	} {
		if !ids[id] {
			t.Errorf("index.html has no id=%q, which app.js binds to", id)
		}
	}

	// The admin-only navigation must exist for the role filter to have targets.
	if !strings.Contains(html, "admin-only") || !strings.Contains(js, "'.admin-only'") {
		t.Error("the admin-only shell elements and their role filter no longer line up")
	}
}

// TestAssetsAreRevalidated guards the upgrade path: the embedded files have no
// mtime, so without a cache validator a browser is free to keep running the
// previous build's app.js — which is exactly how a new panel goes "missing".
func TestAssetsAreRevalidated(t *testing.T) {
	h := Handler()

	for _, name := range []string{"/", "/app.js", "/app.css", "/loginenc.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, name, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", name, rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q, want \"no-cache\"", name, cc)
		}
		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("GET %s: no ETag; a browser may serve this build's asset after an upgrade", name)
		}

		// A conditional request with that ETag must be a 304, so revalidation
		// costs nothing on every page load.
		req := httptest.NewRequest(http.MethodGet, name, nil)
		req.Header.Set("If-None-Match", etag)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Errorf("GET %s with If-None-Match = %d, want 304", name, rec.Code)
		}
	}

	// The SPA fallback still has to hand back the shell for unknown routes.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/collections", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>PostLite</title>") {
		t.Errorf("SPA fallback: got %d, body starts %q", rec.Code, firstLine(rec.Body.String()))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
