package script

import (
	"regexp"
	"strings"
	"testing"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDV4(t *testing.T) {
	out := runJS(t, `
		const uuid = pm.require('npm:uuid@9.0.0');
		const ids = [];
		for (let i = 0; i < 500; i++) ids.push(uuid.v4());
		globalThis.out = {
			first: ids[0],
			unique: new Set(ids).size,
			version: uuid.version(ids[0]),
			valid: uuid.validate(ids[0]),
		};
	`)
	first, _ := out["first"].(string)
	if !uuidV4Re.MatchString(first) {
		t.Fatalf("v4 = %q, want a canonical version-4 uuid", first)
	}
	if got := out["unique"]; got != int64(500) {
		t.Errorf("unique count = %v, want 500", got)
	}
	if got := out["version"]; got != int64(4) {
		t.Errorf("version = %v, want 4", got)
	}
	if out["valid"] != true {
		t.Error("validate() rejected a generated v4")
	}
}

func TestUUIDV1(t *testing.T) {
	out := runJS(t, `
		const uuid = pm.require('npm:uuid@9.0.0');
		const ids = [];
		for (let i = 0; i < 100; i++) ids.push(uuid.v1());
		globalThis.out = {
			first: ids[0],
			unique: new Set(ids).size,
			version: uuid.version(ids[0]),
			variant: ids[0][19],
		};
	`)
	first, _ := out["first"].(string)
	if len(first) != 36 || strings.Count(first, "-") != 4 {
		t.Fatalf("v1 = %q, want a canonical uuid", first)
	}
	if got := out["unique"]; got != int64(100) {
		t.Errorf("unique count = %v, want 100", got)
	}
	if got := out["version"]; got != int64(1) {
		t.Errorf("version = %v, want 1", got)
	}
	if v, _ := out["variant"].(string); v != "8" && v != "9" && v != "a" && v != "b" {
		t.Errorf("variant nibble = %v, want 8/9/a/b", out["variant"])
	}
}

func TestUUIDV5Vector(t *testing.T) {
	// The well-known example: v5 of the DNS namespace and "www.example.com".
	out := runJS(t, `
		const uuid = pm.require('npm:uuid@9.0.0');
		globalThis.out = {
			dnsDefault: uuid.v5('www.example.com'),
			dnsExplicit: uuid.v5('www.example.com', uuid.DNS),
			url: uuid.v5('www.example.com', uuid.URL),
			version: uuid.version(uuid.v5('www.example.com')),
		};
	`)
	if got := out["dnsDefault"]; got != "2ed6657d-e927-568b-95e1-2665a8aea6a2" {
		t.Errorf("v5(DNS, www.example.com) = %v", got)
	}
	if out["dnsDefault"] != out["dnsExplicit"] {
		t.Error("the default namespace is not DNS")
	}
	if out["url"] == out["dnsDefault"] {
		t.Error("a different namespace must give a different uuid")
	}
	if got := out["version"]; got != int64(5) {
		t.Errorf("version = %v, want 5", got)
	}
}

func TestUUIDValidateVersionParse(t *testing.T) {
	out := runJS(t, `
		const uuid = pm.require('npm:uuid@9.0.0');
		const parsed = uuid.parse('2ed6657d-e927-568b-95e1-2665a8aea6a2');
		globalThis.out = {
			validNIL: uuid.validate(uuid.NIL),
			validUpper: uuid.validate('2ED6657D-E927-568B-95E1-2665A8AEA6A2'),
			validBraced: uuid.validate('{2ed6657d-e927-568b-95e1-2665a8aea6a2}'),
			validShort: uuid.validate('2ed6657d-e927-568b-95e1-2665a8aea6a'),
			validJunk: uuid.validate('not-a-uuid'),
			parsedType: Object.prototype.toString.call(parsed),
			parsedLen: parsed.length,
			roundTrip: uuid.stringify(parsed),
			bracedParse: uuid.stringify(uuid.parse('{2ed6657d-e927-568b-95e1-2665a8aea6a2}')),
			nil: uuid.NIL,
			max: uuid.MAX,
		};
	`)
	for field, want := range map[string]any{
		"validNIL":    true,
		"validUpper":  true,
		"validBraced": true,
		"validShort":  false,
		"validJunk":   false,
		"parsedType":  "[object Uint8Array]",
		"parsedLen":   int64(16),
		"roundTrip":   "2ed6657d-e927-568b-95e1-2665a8aea6a2",
		"bracedParse": "2ed6657d-e927-568b-95e1-2665a8aea6a2",
		"nil":         "00000000-0000-0000-0000-000000000000",
		"max":         "ffffffff-ffff-ffff-ffff-ffffffffffff",
	} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestUUIDErrors(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"version", "pm.require('npm:uuid@9.0.0').version('nope')", "invalid uuid"},
		{"parse", "pm.require('npm:uuid@9.0.0').parse('nope')", "invalid uuid"},
		{"stringifyLength", "pm.require('npm:uuid@9.0.0').stringify(new Uint8Array(4))", "bad length: 4 (want 16)"},
		{"v5Namespace", "pm.require('npm:uuid@9.0.0').v5('x', 'nope')", "invalid uuid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectJSError(t, tc.body, tc.want)
		})
	}
}

func TestUUIDRequireAliasesShareOneInstance(t *testing.T) {
	out := runJS(t, `
		const a = pm.require('npm:uuid@9.0.0');
		const b = pm.require('npm:uuid');
		const c = pm.require('uuid');
		globalThis.out = {same: a === b && b === c, v4: typeof a.v4};
	`)
	if out["same"] != true {
		t.Error("module aliases returned different objects")
	}
	if out["v4"] != "function" {
		t.Errorf("v4 = %v, want a function", out["v4"])
	}
}
