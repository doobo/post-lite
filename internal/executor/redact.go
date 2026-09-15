package executor

import (
	"fmt"
	"sort"
	"strings"
)

// Redactor replaces sensitive values with "***" in text and headers.
// Sensitive values are the decrypted secret values injected during
// resolution, plus common sensitive response headers.
type Redactor struct {
	values []string // longest-first, deduped
}

// NewRedactor builds a redactor from the set of secret values that may
// appear in requests/responses.
func NewRedactor(values []string) *Redactor {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	// Replace longest values first to avoid partial overlaps.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return &Redactor{values: out}
}

// Text masks every occurrence of a sensitive value with "***".
func (r *Redactor) Text(s string) string {
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, "***")
	}
	return s
}

// SensitiveHeaders are response/request headers that are always masked.
// Keys are lowercase; lookups use strings.ToLower.
var SensitiveHeaders = map[string]struct{}{
	"set-cookie":          {},
	"cookie":              {},
	"authorization":       {},
	"x-api-key":           {},
	"proxy-authorization": {},
}

// Headers returns a copy of h with sensitive values masked.
func (r *Redactor) Headers(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		nk := k
		lk := strings.ToLower(k)
		if _, sens := SensitiveHeaders[lk]; sens {
			out[nk] = []string{"***"}
			continue
		}
		redacted := make([]string, len(vs))
		for i, v := range vs {
			redacted[i] = r.Text(v)
		}
		out[nk] = redacted
	}
	return out
}

// RequestSnapshot builds a redacted, single-line-ish request record.
func (r *Redactor) RequestSnapshot(method, url string, headers map[string][]string, body string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(r.Text(url))
	b.WriteString("\n")
	if len(headers) > 0 {
		names := make([]string, 0, len(headers))
		for k := range headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			lk := strings.ToLower(k)
			for _, v := range headers[k] {
				if _, sens := SensitiveHeaders[lk]; sens {
					b.WriteString(k + ": ***\n")
					continue
				}
				b.WriteString(k + ": " + r.Text(v) + "\n")
			}
		}
		b.WriteString("\n")
	}
	if body != "" {
		b.WriteString("Body:\n")
		b.WriteString(r.Text(body))
	}
	return b.String()
}

// ResponseSnapshot builds a redacted response record.
func (r *Redactor) ResponseSnapshot(status int, headers map[string][]string, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\n", status)
	if len(headers) > 0 {
		names := make([]string, 0, len(headers))
		for k := range headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			lk := strings.ToLower(k)
			for _, v := range headers[k] {
				if _, sens := SensitiveHeaders[lk]; sens {
					b.WriteString(k + ": ***\n")
					continue
				}
				b.WriteString(k + ": " + r.Text(v) + "\n")
			}
		}
		b.WriteString("\n")
	}
	if body != "" {
		b.WriteString(r.Text(body))
	}
	return b.String()
}
