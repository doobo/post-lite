package script

import (
	"reflect"
	"testing"

	"github.com/dop251/goja"
)

type fakeModule struct{ id string }

func (f fakeModule) ID() string { return f.id }

func (f fakeModule) Register(vm *goja.Runtime) goja.Value { return vm.ToValue(f.id) }

func TestNormalizeModuleID(t *testing.T) {
	cases := map[string]string{
		"npm:tweetnacl@1.0.3":  "tweetnacl",
		"tweetnacl@1.0.3":      "tweetnacl",
		"npm:tweetnacl":        "tweetnacl",
		"TweetNacl":            "tweetnacl",
		"  npm:uuid@9.0.0  ":   "uuid",
		"@scope/pkg@1.2.3":     "@scope/pkg",
		"@scope/pkg":           "@scope/pkg",
		"npm:@scope/pkg@2":     "@scope/pkg",
		"npm:tweetnacl@1.0.3@": "tweetnacl@1.0.3",
	}
	for in, want := range cases {
		if got := normalizeModuleID(in); got != want {
			t.Errorf("normalizeModuleID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistryLookupAliases(t *testing.T) {
	reg := NewRegistry(TweetNaclModule{})
	for _, name := range []string{
		"npm:tweetnacl@1.0.3",
		"npm:tweetnacl@0.9.0", // a script pinned to another version still resolves
		"tweetnacl",
		"npm:TweetNacl",
	} {
		m, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q) not found", name)
		}
		if m.ID() != tweetNaclID {
			t.Fatalf("Lookup(%q) = %s, want %s", name, m.ID(), tweetNaclID)
		}
	}
	if _, ok := reg.Lookup("npm:lodash@4.17.21"); ok {
		t.Fatal("unexpected module looked up")
	}
}

func TestRegistryIDs(t *testing.T) {
	want := []string{"npm:tweetnacl@1.0.3", "npm:uuid@9.0.0"}
	if got := DefaultRegistry().IDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultRegistry().IDs() = %v, want %v", got, want)
	}
	if got := NewRegistry().IDs(); len(got) != 0 {
		t.Fatalf("empty registry IDs = %v", got)
	}
}

func TestRegistryRegisterReplaces(t *testing.T) {
	reg := NewRegistry(TweetNaclModule{})
	reg.Register(fakeModule{id: "npm:tweetnacl@2.0.0"})
	m, ok := reg.Lookup("npm:tweetnacl@1.0.3")
	if !ok {
		t.Fatal("module not found")
	}
	if m.ID() != "npm:tweetnacl@2.0.0" {
		t.Fatalf("last registration did not win, got %s", m.ID())
	}
	// Same normalized name: one entry, not two.
	if ids := reg.IDs(); len(ids) != 1 {
		t.Fatalf("IDs() = %v, want a single entry", ids)
	}
}

func TestNilRegistryIsUsable(t *testing.T) {
	var reg *Registry
	reg.Register(TweetNaclModule{}) // must not panic
	if _, ok := reg.Lookup("tweetnacl"); ok {
		t.Fatal("nil registry returned a module")
	}
	if reg.IDs() != nil {
		t.Fatal("nil registry returned IDs")
	}
}
