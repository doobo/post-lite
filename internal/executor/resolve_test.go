package executor

import (
	"sort"
	"testing"
)

func TestResolveSubstitutesValuesAndSecrets(t *testing.T) {
	r := NewResolver(
		map[string]string{"host": "10.0.0.1"},
		func(name string) (string, bool) {
			if name == "api_key" {
				return "S3CRET", true
			}
			return "", false
		},
	)

	got, warns := r.Resolve("http://{{host}}/v1?k={{sec.api_key}}")
	if got != "http://10.0.0.1/v1?k=S3CRET" {
		t.Fatalf("Resolve = %q, want the substituted URL", got)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %v, want none", warns)
	}
	// Injected secret values are handed to the redactor.
	if used := r.UsedSecrets(); len(used) != 1 || used[0] != "S3CRET" {
		t.Fatalf("UsedSecrets = %v, want [S3CRET]", used)
	}
}

func TestResolveKeepsUnknownPlaceholdersAndWarns(t *testing.T) {
	r := NewResolver(nil, func(string) (string, bool) { return "", false })

	got, warns := r.Resolve("{{a}}/{{a}}/{{b}}")
	if got != "{{a}}/{{a}}/{{b}}" {
		t.Fatalf("Resolve = %q, want the placeholders preserved", got)
	}
	sort.Strings(warns)
	if len(warns) != 2 || warns[0] != "a" || warns[1] != "b" {
		t.Fatalf("warnings = %v, want [a b] with duplicates collapsed", warns)
	}
	if w := r.Warnings(); len(w) != 2 {
		t.Fatalf("Warnings = %v, want 2 entries", w)
	}
}

func TestResolveMissingSecretWarnsAndInjectsNothing(t *testing.T) {
	r := NewResolver(nil, func(string) (string, bool) { return "", false })

	got, warns := r.Resolve("{{sec.missing}}")
	if got != "{{sec.missing}}" {
		t.Fatalf("Resolve = %q, want the placeholder preserved", got)
	}
	if len(warns) != 1 || warns[0] != "sec.missing" {
		t.Fatalf("warnings = %v, want [sec.missing]", warns)
	}
	if used := r.UsedSecrets(); len(used) != 0 {
		t.Fatalf("UsedSecrets = %v, want none", used)
	}
}

func TestResolvePrefersValuesOverVault(t *testing.T) {
	hookCalled := false
	r := NewResolver(
		map[string]string{"sec.k": "from-values"},
		func(string) (string, bool) { hookCalled = true; return "from-vault", true },
	)

	got, _ := r.Resolve("{{sec.k}}")
	if got != "from-values" {
		t.Fatalf("Resolve = %q, want the environment value to win", got)
	}
	if hookCalled {
		t.Error("the vault was consulted even though the value was already defined")
	}
	if used := r.UsedSecrets(); len(used) != 0 {
		t.Errorf("UsedSecrets = %v; a value-map hit is not an injected secret", used)
	}
}
