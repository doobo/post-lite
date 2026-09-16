// Package script implements post-lite's Postman-compatible JavaScript sandbox.
//
// The design goal (see docs/post-lite-script.md) is to keep running existing
// Postman scripts without Node.js, without npm and without downloading anything
// at run time: pm.require() resolves npm names against a registry of modules
// implemented in Go, so `pm.require('npm:tweetnacl@1.0.3')` reaches
// crypto/ed25519 instead of the internet.
//
// Two tracks are offered for the same operations:
//
//	// compatibility layer — an old script keeps working verbatim
//	const nacl = pm.require('npm:tweetnacl@1.0.3');
//	const keyPair = nacl.sign.keyPair.fromSeed(seed);
//	const signature = nacl.sign.detached(message, keyPair.secretKey);
//
//	// native API — shorter for new scripts
//	const signature = pm.crypto.ed25519.sign({seed, data, outputEncoding: 'base64'});
//
// The globals a script sees are exactly: `pm`, `console`, the Postman/browser
// helpers scripts assume (atob / btoa / TextEncoder / TextDecoder), standard
// ECMAScript, and whatever the embedding program added with Runtime.Set. There
// is no filesystem, no network and no npm, so a script cannot reach outside the
// values it was handed.
package script

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// ErrTimeout is the error a script run interrupted by WithTimeout reports
// (via *goja.InterruptedError). Use errors.Is.
var ErrTimeout = errors.New("script execution timed out")

// Runtime is one JS context plus its `pm` object. It is not safe for concurrent
// use: a goja VM is single-threaded, so give each execution its own Runtime.
type Runtime struct {
	vm       *goja.Runtime
	pm       *goja.Object // the `pm` object, so BindRequest can extend it
	registry *Registry
	modules  map[string]goja.Value // canonical ID -> JS value (require cache)
	timeout  time.Duration
	console  io.Writer
	// tests collects pm.test / tests[...] results for one execution (pre-request
	// and post-response alike). The pipeline builds one Runtime per execution,
	// so this never leaks between requests.
	tests []TestResult
}

// Option configures a Runtime.
type Option func(*Runtime)

// WithRegistry replaces the module registry (default: DefaultRegistry).
func WithRegistry(reg *Registry) Option {
	return func(r *Runtime) {
		if reg != nil {
			r.registry = reg
		}
	}
}

// WithTimeout interrupts a script that runs longer than d. Zero (the default)
// means no limit.
func WithTimeout(d time.Duration) Option {
	return func(r *Runtime) { r.timeout = d }
}

// WithConsole sends console.log/warn/error output to w (default: os.Stderr).
func WithConsole(w io.Writer) Option {
	return func(r *Runtime) {
		if w != nil {
			r.console = w
		}
	}
}

// New returns a Runtime with the builtin modules and the `pm` object installed.
func New(opts ...Option) *Runtime {
	r := &Runtime{
		vm:       goja.New(),
		registry: DefaultRegistry(),
		modules:  map[string]goja.Value{},
		console:  os.Stderr,
	}
	for _, o := range opts {
		o(r)
	}
	r.install()
	return r
}

// VM exposes the underlying goja runtime, for host functions the embedding
// program wants to add (Runtime.Set is a shortcut for the common case).
func (r *Runtime) VM() *goja.Runtime { return r.vm }

// Registry exposes the module registry.
func (r *Runtime) Registry() *Registry { return r.registry }

// Set defines a global for scripts to read.
func (r *Runtime) Set(name string, value any) error { return r.vm.Set(name, value) }

// Get reads a global (nil when it is not defined).
func (r *Runtime) Get(name string) goja.Value { return r.vm.Get(name) }

// Require resolves a module name the way pm.require does, for Go callers. The
// module is built once per Runtime and then cached, so two require calls with
// aliases ("npm:uuid", "npm:uuid@9.0.0") return the same object.
func (r *Runtime) Require(name string) (goja.Value, error) {
	mod, ok := r.registry.Lookup(name)
	if !ok {
		ids := r.registry.IDs()
		if len(ids) == 0 {
			return nil, fmt.Errorf("cannot find module '%s': this runtime has an empty module registry", name)
		}
		return nil, fmt.Errorf("cannot find module '%s': post-lite serves built-in modules only (%s)",
			name, strings.Join(ids, ", "))
	}
	if v, ok := r.modules[mod.ID()]; ok {
		return v, nil
	}
	v := mod.Register(r.vm)
	r.modules[mod.ID()] = v
	return v, nil
}

// Run executes src in the VM with name used for stack traces and error
// messages (say "pre-request.js").
func (r *Runtime) Run(name, src string) (goja.Value, error) {
	prog, err := goja.Compile(name, src, false)
	if err != nil {
		return nil, err
	}
	return r.RunProgram(prog)
}

// RunFile reads and runs a script from disk.
func (r *Runtime) RunFile(path string) (goja.Value, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return r.Run(filepath.Base(path), string(src))
}

// RunProgram runs an already-compiled program, applying the WithTimeout budget.
func (r *Runtime) RunProgram(prog *goja.Program) (goja.Value, error) {
	done := r.startDeadline()
	defer done()
	return r.vm.RunProgram(prog)
}

// Interrupt aborts the running script, from another goroutine, with reason as
// the error value (ErrTimeout by default via WithTimeout).
func (r *Runtime) Interrupt(reason any) { r.vm.Interrupt(reason) }

func (r *Runtime) startDeadline() func() {
	if r.timeout <= 0 {
		return func() {}
	}
	timer := time.AfterFunc(r.timeout, func() { r.vm.Interrupt(ErrTimeout) })
	return func() {
		timer.Stop()
		// A fired timer leaves the VM interrupted, which would poison the next
		// Run on this Runtime; clearing it here also resets an external
		// Interrupt() once the run it was aimed at has finished.
		r.vm.ClearInterrupt()
	}
}

// install builds the `pm` object and the compatibility globals.
func (r *Runtime) install() {
	pm := r.vm.NewObject()
	pm.Set("require", func(call goja.FunctionCall) goja.Value {
		v, err := r.Require(call.Argument(0).String())
		if err != nil {
			throwType(r.vm, "%v", err)
		}
		return v
	})
	pm.Set("crypto", cryptoModule(r.vm))
	r.installTestHelpers(pm)
	r.pm = pm

	if err := r.vm.Set("pm", pm); err != nil {
		panic("script: install pm: " + err.Error())
	}
	// Bind an empty Env up front, so a Runtime the host never bound (script.New
	// used on its own, or a script that runs before the request is known) still
	// answers pm.request / pm.variables instead of throwing a TypeError about
	// those objects being undefined. pm.variables.get('NAME') for an unset name
	// then returns undefined, which is a fact about the request and something
	// the script can act on — the sandbox bug the other message implied is not.
	r.Bind(NewEnv(nil, nil))
	r.installConsole()
	r.installCompatGlobals()
}

// installConsole gives scripts the console.log/warn/error they expect, with the
// printf-style substitution Node and Postman do (console.log('t=%s', t)). Output
// goes to the Runtime's writer and never throws, so a stray console.log cannot
// fail a request.
func (r *Runtime) installConsole() {
	console := r.vm.NewObject()
	write := func(call goja.FunctionCall) goja.Value {
		if r.console == nil {
			return goja.Undefined()
		}
		_, _ = fmt.Fprintln(r.console, formatConsoleArgs(call.Arguments))
		return goja.Undefined()
	}
	for _, name := range []string{"log", "info", "warn", "error", "debug", "trace"} {
		console.Set(name, write)
	}
	if err := r.vm.Set("console", console); err != nil {
		panic("script: install console: " + err.Error())
	}
}

// formatConsoleArgs joins console arguments, expanding the %s/%d/%i/%f/%j/%o/%%
// placeholders of a leading format string when there are further arguments.
func formatConsoleArgs(args []goja.Value) string {
	if len(args) == 0 {
		return ""
	}
	format := args[0].String()
	if len(args) == 1 || !strings.Contains(format, "%") {
		parts := make([]string, 0, len(args))
		for _, a := range args {
			parts = append(parts, consoleArg(a))
		}
		return strings.Join(parts, " ")
	}

	rest := args[1:]
	var b strings.Builder
	used := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) || used >= len(rest) {
			b.WriteByte(format[i])
			continue
		}
		switch format[i+1] {
		case 's':
			b.WriteString(rest[used].String())
		case 'd', 'i':
			b.WriteString(strconv.FormatInt(rest[used].ToInteger(), 10))
		case 'f':
			b.WriteString(strconv.FormatFloat(rest[used].ToFloat(), 'f', -1, 64))
		case 'j', 'o', 'O':
			b.WriteString(jsonArg(rest[used]))
		case '%':
			b.WriteByte('%')
			i++
			continue
		default:
			b.WriteByte(format[i])
			continue
		}
		i++
		used++
	}
	for ; used < len(rest); used++ {
		b.WriteByte(' ')
		b.WriteString(consoleArg(rest[used]))
	}
	return b.String()
}

// consoleArg renders an argument for the no-placeholder path: objects and arrays
// as JSON rather than the useless "[object Object]".
func consoleArg(v goja.Value) string {
	if _, ok := v.(*goja.Object); ok {
		if _, isFunc := goja.AssertFunction(v); !isFunc {
			return jsonArg(v)
		}
	}
	return v.String()
}

// jsonArg renders %j / %o the way JSON.stringify would.
func jsonArg(v goja.Value) string {
	if obj, ok := v.(*goja.Object); ok {
		if raw, err := json.Marshal(obj); err == nil {
			return string(raw)
		}
	}
	if exported, err := safeExport(v); err == nil {
		if raw, err := json.Marshal(exported); err == nil {
			return string(raw)
		}
	}
	return v.String()
}

// throwType throws a JS TypeError. Every Go callback reports a bad argument this
// way, so the script sees a normal exception with a message that names the
// field that is wrong.
func throwType(vm *goja.Runtime, format string, args ...any) {
	panic(vm.NewTypeError(fmt.Sprintf(format, args...)))
}
