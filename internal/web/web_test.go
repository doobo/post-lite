package web

import (
	"io/fs"
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
