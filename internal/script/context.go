package script

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dop251/goja"
)

// RequestCtx is the mutable pre-request view of the outbound request: what the
// script reads through pm.request, and what the caller reads back after Run to
// build the real request.
//
// URL and Body still contain {{VAR}} / {{sec.NAME}} placeholders on purpose —
// the script runs *before* variable resolution, so it can inject a placeholder
// (or a signature) and let the server expand secrets afterwards, which is what
// keeps secret values out of the script's reach.
type RequestCtx struct {
	Method   string
	URL      string
	BodyType string
	Body     string
	// Headers keeps insertion order; a repeated key is allowed here and
	// collapses in HeaderMap (the executor takes a map, so last one wins).
	Headers [][2]string
}

// Env binds request/response state and a variable bag to a Runtime: pm.request,
// pm.response and pm.variables/* then point straight at this state.
//
// Vars is the merged view a script gets to read and write (global env, then
// user env, then the editor's temporary vars, per the resolver's precedence).
// A write is local to this execution: nothing is persisted back to an
// environment, which keeps a script from silently rewriting shared config.
//
// Response is nil for a pre-request script and set for a post-response one; the
// same Env can be reused across both phases, which is how a variable set before
// the request stays visible to the assertions after it.
type Env struct {
	Request  *RequestCtx
	Response *ResponseCtx
	Vars     map[string]string
	// Changed holds the names the script wrote, so the caller can show what a
	// script actually did without diffing maps.
	Changed map[string]string
}

// NewEnv builds an Env, copying vars so a script cannot reach the caller's map.
func NewEnv(req *RequestCtx, vars map[string]string) *Env {
	if req == nil {
		req = &RequestCtx{}
	}
	bag := make(map[string]string, len(vars))
	for k, v := range vars {
		bag[k] = v
	}
	return &Env{Request: req, Vars: bag, Changed: map[string]string{}}
}

// SetVar records a script write.
func (e *Env) SetVar(name, value string) {
	e.Vars[name] = value
	e.Changed[name] = value
}

// HeaderMap flattens the header list into what executor.In wants.
func (e *Env) HeaderMap() map[string]string {
	out := make(map[string]string, len(e.Request.Headers))
	for _, h := range e.Request.Headers {
		out[h[0]] = h[1]
	}
	return out
}

// SortedHeaders builds the initial header list from a map, in a stable order so
// a script's output (and test expectations) do not depend on Go's map order.
func SortedHeaders(headers map[string]string) [][2]string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, headers[k]})
	}
	return out
}

// Bind installs pm.request, pm.response and the variable scopes on the runtime.
// Call it before Run; afterwards read the mutations off the Env. Binding again
// with the same Env (a post-response script after the request went out) is
// expected: the variable bag and the test results carry over.
func (r *Runtime) Bind(env *Env) {
	if env == nil {
		return
	}
	if env.Vars == nil {
		env.Vars = map[string]string{}
	}
	if env.Changed == nil {
		env.Changed = map[string]string{}
	}
	if r.pm == nil {
		return
	}
	r.pm.Set("request", requestObject(r.vm, env))
	if env.Response != nil {
		r.pm.Set("response", responseObject(r.vm, env.Response))
	}
	// post-lite keeps one merged variable bag, so the three Postman scopes are
	// views of the same data. Scripts written for pm.environment/pm.globals
	// therefore keep working instead of failing on a missing object.
	for _, name := range []string{"variables", "environment", "globals"} {
		r.pm.Set(name, scopeObject(r.vm, env))
	}
}

/* ---------- pm.request ---------- */

func requestObject(vm *goja.Runtime, env *Env) *goja.Object {
	req := vm.NewObject()
	defineStringAccessor(vm, req, "method",
		func() string { return env.Request.Method },
		func(s string) { env.Request.Method = s })

	urlObj := urlObject(vm, env)
	defineAccessor(vm, req, "url",
		func(goja.FunctionCall) goja.Value { return urlObj },
		func(call goja.FunctionCall) goja.Value {
			// Accepts a plain string as well as another Url object.
			env.Request.URL = call.Argument(0).String()
			return goja.Undefined()
		})

	bodyObj := bodyObject(vm, env)
	defineAccessor(vm, req, "body",
		func(goja.FunctionCall) goja.Value { return bodyObj },
		func(call goja.FunctionCall) goja.Value {
			env.Request.Body = call.Argument(0).String()
			return goja.Undefined()
		})

	req.Set("headers", headerObject(vm, env))
	req.Set("toString", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(env.Request.Method + " " + env.Request.URL)
	})
	return req
}

// urlObject exposes the Postman Url surface scripts actually use. It works on
// the raw string rather than net/url, because a URL carrying {{VAR}} or an
// unparseable value must not make the whole script throw.
func urlObject(vm *goja.Runtime, env *Env) *goja.Object {
	url := vm.NewObject()
	url.Set("toString", func(goja.FunctionCall) goja.Value { return vm.ToValue(env.Request.URL) })
	url.Set("update", func(call goja.FunctionCall) goja.Value {
		env.Request.URL = call.Argument(0).String()
		return url
	})
	url.Set("getPathWithQuery", func(goja.FunctionCall) goja.Value {
		return vm.ToValue(pathAndQuery(env.Request.URL))
	})
	url.Set("getPath", func(goja.FunctionCall) goja.Value {
		pq := pathAndQuery(env.Request.URL)
		if i := strings.IndexByte(pq, '?'); i >= 0 {
			return vm.ToValue(pq[:i])
		}
		return vm.ToValue(pq)
	})
	url.Set("getQueryString", func(goja.FunctionCall) goja.Value {
		pq := pathAndQuery(env.Request.URL)
		if i := strings.IndexByte(pq, '?'); i >= 0 {
			return vm.ToValue(pq[i+1:])
		}
		return vm.ToValue("")
	})
	url.Set("getHost", func(goja.FunctionCall) goja.Value { return vm.ToValue(hostOf(env.Request.URL)) })
	// `pm.request.url` also reads as the URL text in template literals.
	defineStringAccessor(vm, url, "value", func() string { return env.Request.URL }, func(s string) { env.Request.URL = s })
	return url
}

// pathAndQuery returns "/path?query" for any URL shape, including a relative
// one, without ever failing: "http://h:5680/a?b=1" -> "/a?b=1".
func pathAndQuery(raw string) string {
	if raw == "" {
		return "/"
	}
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	if strings.HasPrefix(rest, "/") {
		return rest
	}
	return "/" + rest
}

// hostOf returns "host[:port]" ("" when the URL is relative).
func hostOf(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		return rest[:j]
	}
	return rest
}

func bodyObject(vm *goja.Runtime, env *Env) *goja.Object {
	body := vm.NewObject()
	defineStringAccessor(vm, body, "raw",
		func() string { return env.Request.Body },
		func(s string) { env.Request.Body = s })
	// mode is the stored body_type (a plain string, like Postman's), not a
	// function: scripts read it as pm.request.body.mode.
	body.Set("mode", env.Request.BodyType)
	body.Set("update", func(call goja.FunctionCall) goja.Value {
		if obj, ok := call.Argument(0).(*goja.Object); ok {
			if raw := obj.Get("raw"); raw != nil && !goja.IsUndefined(raw) {
				env.Request.Body = raw.String()
			}
		}
		return body
	})
	body.Set("toString", func(goja.FunctionCall) goja.Value { return vm.ToValue(env.Request.Body) })
	return body
}

/* ---------- pm.request.headers ---------- */

func headerObject(vm *goja.Runtime, env *Env) *goja.Object {
	headers := vm.NewObject()

	find := func(name string) int {
		for i, h := range env.Request.Headers {
			if strings.EqualFold(h[0], name) {
				return i
			}
		}
		return -1
	}
	removeAt := func(i int) {
		env.Request.Headers = append(env.Request.Headers[:i], env.Request.Headers[i+1:]...)
	}
	headerValue := func(h [2]string) *goja.Object {
		o := vm.NewObject()
		o.Set("key", h[0])
		o.Set("value", h[1])
		return o
	}

	headers.Set("add", func(call goja.FunctionCall) goja.Value {
		k, v, err := headerArg(call.Argument(0))
		if err != nil {
			throwType(vm, "pm.request.headers.add: %v", err)
		}
		env.Request.Headers = append(env.Request.Headers, [2]string{k, v})
		return goja.Undefined()
	})
	headers.Set("upsert", func(call goja.FunctionCall) goja.Value {
		k, v, err := headerArg(call.Argument(0))
		if err != nil {
			throwType(vm, "pm.request.headers.upsert: %v", err)
		}
		// Drop every existing spelling of the key, then append, so an upserted
		// header keeps the order a script asked for.
		for i := len(env.Request.Headers) - 1; i >= 0; i-- {
			if strings.EqualFold(env.Request.Headers[i][0], k) {
				removeAt(i)
			}
		}
		env.Request.Headers = append(env.Request.Headers, [2]string{k, v})
		return goja.Undefined()
	})
	headers.Set("remove", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		for i := len(env.Request.Headers) - 1; i >= 0; i-- {
			if strings.EqualFold(env.Request.Headers[i][0], name) {
				removeAt(i)
			}
		}
		return goja.Undefined()
	})
	headers.Set("get", func(call goja.FunctionCall) goja.Value {
		if i := find(call.Argument(0).String()); i >= 0 {
			return vm.ToValue(env.Request.Headers[i][1])
		}
		return goja.Null()
	})
	headers.Set("has", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(find(call.Argument(0).String()) >= 0)
	})
	headers.Set("all", func(goja.FunctionCall) goja.Value {
		arr := make([]any, 0, len(env.Request.Headers))
		for _, h := range env.Request.Headers {
			arr = append(arr, headerValue(h))
		}
		return vm.ToValue(arr)
	})
	headers.Set("each", func(call goja.FunctionCall) goja.Value {
		fn, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			throwType(vm, "pm.request.headers.each: a function is required")
		}
		for i, h := range env.Request.Headers {
			if _, err := fn(goja.Undefined(), headerValue(h), vm.ToValue(i)); err != nil {
				panic(err)
			}
		}
		return goja.Undefined()
	})
	headers.Set("toObject", func(goja.FunctionCall) goja.Value {
		o := vm.NewObject()
		for _, h := range env.Request.Headers {
			o.Set(h[0], h[1])
		}
		return o
	})
	headers.Set("toString", func(goja.FunctionCall) goja.Value {
		lines := make([]string, 0, len(env.Request.Headers))
		for _, h := range env.Request.Headers {
			lines = append(lines, h[0]+": "+h[1])
		}
		return vm.ToValue(strings.Join(lines, "\n"))
	})
	return headers
}

func headerArg(v goja.Value) (string, string, error) {
	obj, ok := v.(*goja.Object)
	if !ok {
		return "", "", fmt.Errorf("expected {key, value}, got %s", describe(v))
	}
	k := obj.Get("key")
	val := obj.Get("value")
	if k == nil || goja.IsUndefined(k) {
		return "", "", fmt.Errorf("key is required")
	}
	value := ""
	if val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
		value = val.String()
	}
	return k.String(), value, nil
}

/* ---------- pm.variables / pm.environment / pm.globals ---------- */

var placeholderRe = regexp.MustCompile(`\{\{([\w.]+)\}\}`)

func scopeObject(vm *goja.Runtime, env *Env) *goja.Object {
	scope := vm.NewObject()
	scope.Set("get", func(call goja.FunctionCall) goja.Value {
		if v, ok := env.Vars[call.Argument(0).String()]; ok {
			return vm.ToValue(v)
		}
		return goja.Undefined()
	})
	scope.Set("set", func(call goja.FunctionCall) goja.Value {
		env.SetVar(call.Argument(0).String(), call.Argument(1).String())
		return goja.Undefined()
	})
	scope.Set("has", func(call goja.FunctionCall) goja.Value {
		_, ok := env.Vars[call.Argument(0).String()]
		return vm.ToValue(ok)
	})
	scope.Set("unset", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		delete(env.Vars, name)
		delete(env.Changed, name)
		return goja.Undefined()
	})
	scope.Set("toObject", func(goja.FunctionCall) goja.Value {
		o := vm.NewObject()
		names := make([]string, 0, len(env.Vars))
		for k := range env.Vars {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			o.Set(k, env.Vars[k])
		}
		return o
	})
	// replaceIn resolves {{NAME}} from this bag and leaves anything unknown
	// ({{sec.NAME}} included) in place for the server-side resolver to handle.
	scope.Set("replaceIn", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		return vm.ToValue(placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
			name := m[2 : len(m)-2]
			if v, ok := env.Vars[name]; ok {
				return v
			}
			return m
		}))
	})
	return scope
}

/* ---------- accessor helpers ---------- */

// defineAccessor installs a getter/setter pair directly.
func defineAccessor(vm *goja.Runtime, obj *goja.Object, name string, get func(goja.FunctionCall) goja.Value, set func(goja.FunctionCall) goja.Value) {
	var setter goja.Value = goja.Undefined()
	if set != nil {
		setter = vm.ToValue(set)
	}
	err := obj.DefineAccessorProperty(name,
		vm.ToValue(get), setter, goja.FLAG_TRUE, goja.FLAG_TRUE)
	if err != nil {
		panic(fmt.Sprintf("script: define %s: %v", name, err))
	}
}

// defineGetter installs a read-only accessor (chai-style assertion properties).
func defineGetter(vm *goja.Runtime, obj *goja.Object, name string, get func(goja.FunctionCall) goja.Value) {
	defineAccessor(vm, obj, name, get, nil)
}

// defineStringAccessor is defineAccessor for a plain string property.
func defineStringAccessor(vm *goja.Runtime, obj *goja.Object, name string, get func() string, set func(string)) {
	defineAccessor(vm, obj, name,
		func(goja.FunctionCall) goja.Value { return vm.ToValue(get()) },
		func(call goja.FunctionCall) goja.Value {
			set(call.Argument(0).String())
			return goja.Undefined()
		})
}
