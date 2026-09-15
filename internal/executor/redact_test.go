package executor

import (
	"strings"
	"testing"
)

const testSecret = "s3cr3t-token-value"

func TestRedactorMasksSecretValues(t *testing.T) {
	r := NewRedactor([]string{testSecret})
	got := r.Text("Authorization: Bearer " + testSecret)
	if strings.Contains(got, testSecret) {
		t.Fatalf("Text leaked the secret: %q", got)
	}
	if got != "Authorization: Bearer ***" {
		t.Fatalf("Text = %q, want %q", got, "Authorization: Bearer ***")
	}
}

func TestRedactorIgnoresEmptyValues(t *testing.T) {
	r := NewRedactor([]string{"", testSecret})
	if got := r.Text("prefix-" + testSecret); got != "prefix-***" {
		t.Fatalf("Text = %q, want prefix-***", got)
	}
	// An empty "secret" must not mangle unrelated text.
	if got := r.Text("nothing to mask"); got != "nothing to mask" {
		t.Fatalf("Text = %q, want the input unchanged", got)
	}
}

func TestRedactorReplacesLongestValueFirst(t *testing.T) {
	r := NewRedactor([]string{"abcd", "abcdefgh"})
	if got := r.Text("x=abcdefgh"); got != "x=***" {
		t.Fatalf("Text = %q, want x=*** (longest match must win)", got)
	}
	if got := r.Text("x=abcd"); got != "x=***" {
		t.Fatalf("Text = %q, want x=***", got)
	}
}

func TestHeadersMasksSensitiveKeys(t *testing.T) {
	r := NewRedactor([]string{testSecret})
	in := map[string][]string{
		"Set-Cookie":    {"sid=deadbeef"},
		"Authorization": {"Bearer " + testSecret},
		"X-Api-Key":     {"raw-key"},
		"Cookie":        {"a=b"},
		"Content-Type":  {"application/json"},
		"X-Echo":        {"prefix-" + testSecret},
	}

	got := r.Headers(in)
	for _, k := range []string{"Set-Cookie", "Authorization", "X-Api-Key", "Cookie"} {
		if vs := got[k]; len(vs) != 1 || vs[0] != "***" {
			t.Errorf("header %s = %v, want [***]", k, vs)
		}
	}
	if v := got["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("Content-Type = %v, want it unchanged", v)
	}
	if v := got["X-Echo"]; len(v) != 1 || strings.Contains(v[0], testSecret) {
		t.Errorf("X-Echo = %v, want the secret masked", v)
	}
	if in["Set-Cookie"][0] != "sid=deadbeef" {
		t.Error("Headers mutated the input map")
	}
}

func TestRequestSnapshotRedactsEveryField(t *testing.T) {
	r := NewRedactor([]string{testSecret})
	snap := r.RequestSnapshot(
		"POST",
		"http://10.0.0.1/api?token="+testSecret,
		map[string][]string{"Authorization": {"Bearer " + testSecret}, "Set-Cookie": {"sid=deadbeef"}},
		`{"key":"`+testSecret+`"}`,
	)
	if strings.Contains(snap, testSecret) {
		t.Fatalf("request snapshot leaked the secret:\n%s", snap)
	}
	if strings.Contains(snap, "deadbeef") {
		t.Fatalf("request snapshot leaked a sensitive header:\n%s", snap)
	}
	for _, want := range []string{"POST", "10.0.0.1", "***"} {
		if !strings.Contains(snap, want) {
			t.Errorf("request snapshot is missing %q:\n%s", want, snap)
		}
	}
}

func TestResponseSnapshotRedactsBodyAndHeaders(t *testing.T) {
	r := NewRedactor([]string{testSecret})
	snap := r.ResponseSnapshot(
		200,
		map[string][]string{"X-Echo": {testSecret}, "Set-Cookie": {"sid=deadbeef"}},
		"body contains "+testSecret,
	)
	if strings.Contains(snap, testSecret) {
		t.Fatalf("response snapshot leaked the secret:\n%s", snap)
	}
	if strings.Contains(snap, "deadbeef") {
		t.Fatalf("response snapshot leaked Set-Cookie:\n%s", snap)
	}
	if !strings.Contains(snap, "HTTP 200") {
		t.Errorf("response snapshot is missing the status line:\n%s", snap)
	}
}
