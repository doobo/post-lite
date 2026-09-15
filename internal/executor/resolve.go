package executor

import (
	"regexp"
	"strings"
)

// varRe matches {{name}} placeholders, allowing dots (e.g. sec.api_key).
var varRe = regexp.MustCompile(`\{\{([\w.]+)\}\}`)

// Resolver substitutes {{VAR}} placeholders.
//
// Resolution precedence (caller builds Values accordingly):
//
//  1. request-level temp vars
//  2. active user environment
//  3. active global environment
//  4. secrets (via the Secret hook, name = part after "sec.")
//
// Unresolved names are left as-is and reported through Warnings.
type Resolver struct {
	Values map[string]string
	Secret func(name string) (string, bool) // name without the "sec." prefix

	warnings map[string]struct{}
	used     map[string]string // secret name -> value (for redaction)
}

func NewResolver(values map[string]string, secret func(string) (string, bool)) *Resolver {
	return &Resolver{
		Values:   values,
		Secret:   secret,
		warnings: map[string]struct{}{},
		used:     map[string]string{},
	}
}

// Resolve returns the substituted text plus any unresolved names.
func (r *Resolver) Resolve(s string) (string, []string) {
	out := varRe.ReplaceAllStringFunc(s, func(m string) string {
		name := varRe.FindStringSubmatch(m)[1]
		if v, ok := r.Values[name]; ok {
			return v
		}
		if rest, found := strings.CutPrefix(name, "sec."); found {
			if v, ok := r.Secret(rest); ok {
				r.used[rest] = v
				return v
			}
		}
		r.warnings[name] = struct{}{}
		return m
	})
	warns := make([]string, 0, len(r.warnings))
	for w := range r.warnings {
		warns = append(warns, w)
	}
	return out, warns
}

// Warnings returns deduplicated unresolved names seen so far.
func (r *Resolver) Warnings() []string {
	out := make([]string, 0, len(r.warnings))
	for w := range r.warnings {
		out = append(out, w)
	}
	return out
}

// UsedSecrets returns the decrypted secret values that were injected during
// resolution. The executor redacts these from history/response snapshots.
func (r *Resolver) UsedSecrets() []string {
	out := make([]string, 0, len(r.used))
	for _, v := range r.used {
		out = append(out, v)
	}
	return out
}
