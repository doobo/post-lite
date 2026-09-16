package script

import (
	"sort"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

// BuiltinModule is a module served by pm.require() from Go, without touching
// the network or the filesystem. A module is identified by an npm-style name
// such as "npm:tweetnacl@1.0.3", which is why an unmodified Postman script can
// keep calling pm.require('npm:tweetnacl@1.0.3').
//
// Adding a module is only ever "implement this interface, then register it":
// the runtime and the pm object do not change.
type BuiltinModule interface {
	// ID is the canonical module name, e.g. "npm:tweetnacl@1.0.3".
	ID() string
	// Register builds the module's JS value (normally an object of functions).
	// It is called at most once per Runtime and the result is cached, so the
	// same module can be handed out to every pm.require() call cheaply.
	Register(vm *goja.Runtime) goja.Value
}

// Registry maps module names to builtin modules.
//
// Lookup is version- and prefix-tolerant: a module registered as
// "npm:tweetnacl@1.0.3" is also found as "npm:tweetnacl", "tweetnacl@1.0.3"
// or plain "tweetnacl", so a script pinned to a different patch release still
// gets the builtin. Registering a second module under the same normalized name
// replaces the first one (last registration wins).
type Registry struct {
	mu      sync.RWMutex
	entries map[string]registryEntry
}

type registryEntry struct {
	id  string // canonical ID, as returned by BuiltinModule.ID()
	mod BuiltinModule
}

// NewRegistry returns a registry with the given modules registered.
// Called with no arguments it is empty; see DefaultRegistry for the builtins
// post-lite ships with.
func NewRegistry(mods ...BuiltinModule) *Registry {
	r := &Registry{entries: map[string]registryEntry{}}
	for _, m := range mods {
		r.Register(m)
	}
	return r
}

// DefaultRegistry is the registry every Runtime starts with.
func DefaultRegistry() *Registry {
	return NewRegistry(TweetNaclModule{}, UUIDModule{})
}

// Register adds (or replaces) a module.
func (r *Registry) Register(m BuiltinModule) {
	if r == nil || m == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string]registryEntry{}
	}
	r.entries[normalizeModuleID(m.ID())] = registryEntry{id: m.ID(), mod: m}
}

// Lookup finds the module serving name, which may be written with or without
// the "npm:" prefix and the "@version" suffix.
func (r *Registry) Lookup(name string) (BuiltinModule, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[normalizeModuleID(name)]
	if !ok {
		return nil, false
	}
	return e.mod, true
}

// IDs returns the canonical IDs of every registered module, sorted.
func (r *Registry) IDs() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.id)
	}
	sort.Strings(out)
	return out
}

// normalizeModuleID strips the "npm:" prefix and a trailing "@version" so that
// "npm:tweetnacl@1.0.3", "tweetnacl@1.0.3" and "npm:TweetNacl" all collapse to
// the same key. A leading "@scope/" is kept, being part of the package name.
func normalizeModuleID(name string) string {
	n := strings.TrimSpace(name)
	n = strings.TrimPrefix(n, "npm:")
	if i := strings.LastIndex(n, "@"); i > 0 {
		n = n[:i]
	}
	return strings.ToLower(n)
}
