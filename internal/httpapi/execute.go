package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"postlite/internal/executor"
	"postlite/internal/repository"
	"postlite/internal/script"
)

// defaultScriptTimeout bounds a pre-request script when the server was started
// without an explicit -script-timeout. Much shorter than the request timeout on
// purpose: the caller is blocked while the script runs.
const defaultScriptTimeout = 5 * time.Second

// maxScriptLogLines / maxScriptLogBytes keep a chatty script from turning the
// execute response into a payload of its own.
const (
	maxScriptLogLines = 200
	maxScriptLogBytes = 64 << 10
)

type executeBody struct {
	RequestID *int64 `json:"request_id"`
	AdHoc     *struct {
		Method   string            `json:"method"`
		URL      string            `json:"url"`
		Headers  map[string]string `json:"headers"`
		Query    []kvPair          `json:"query"`
		BodyType string            `json:"body_type"`
		Body     string            `json:"body"`
		// Variables carries the GraphQL variables document (body_type=graphql).
		Variables string `json:"variables"`
		// Script / TestScript are the pre-request and post-response JS. The UI
		// sends ad_hoc even for saved requests, so they have to ride along here as
		// well as on the stored row.
		Script     string `json:"script"`
		TestScript string `json:"test_script"`
		UseProxy   bool   `json:"use_proxy"`
	} `json:"ad_hoc"`
	Vars            map[string]string `json:"vars"`
	ActiveEnv       *activateBody     `json:"active_env"`
	FollowRedirects bool              `json:"follow_redirects"`
}

// defaultWhitelist is used when the "ssrf_whitelist" setting is empty.
const defaultWhitelist = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"

func (s *Server) execute(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b executeBody
	if !decodeBody(w, r, &b) {
		return
	}

	// Resolve the target: either a stored request or an ad-hoc definition.
	var (
		method    string
		urlStr    string
		headers   map[string]string
		query     [][2]string
		bodyT     string
		body      string
		variables string
		scriptSrc string
		testSrc   string
		reqID     *int64
		useProxy  bool
	)
	switch {
	case b.RequestID != nil:
		rq, err := s.Store.Requests.Get(*b.RequestID)
		if err != nil {
			fail(w, http.StatusNotFound, "not_found", "request not found")
			return
		}
		c, err := s.Store.Collections.Get(rq.CollectionID)
		if err != nil || !s.Store.CanUseRequest(u, rq, c) {
			fail(w, http.StatusForbidden, "forbidden", "cannot access this request")
			return
		}
		reqID = &rq.ID
		method = rq.Method
		urlStr = rq.URL
		bodyT = rq.BodyType
		body = rq.Body
		variables = rq.Variables
		scriptSrc = rq.Script
		testSrc = rq.TestScript
		useProxy = rq.UseProxy
		p := repository.RequestPayload{Headers: rq.Headers, Query: rq.Query}
		headers = p.HeadersMap()
		query = p.QueryPairs()
	case b.AdHoc != nil:
		method = b.AdHoc.Method
		if method == "" {
			method = "GET"
		}
		urlStr = b.AdHoc.URL
		headers = b.AdHoc.Headers
		bodyT = b.AdHoc.BodyType
		body = b.AdHoc.Body
		variables = b.AdHoc.Variables
		scriptSrc = b.AdHoc.Script
		testSrc = b.AdHoc.TestScript
		useProxy = b.AdHoc.UseProxy
		for _, q := range b.AdHoc.Query {
			query = append(query, [2]string{q.K, q.V})
		}
		if urlStr == "" {
			fail(w, http.StatusBadRequest, "bad_request", "url is required")
			return
		}
	default:
		fail(w, http.StatusBadRequest, "bad_request", "request_id or ad_hoc is required")
		return
	}

	// Build the resolver precedence: global env -> user env -> request vars.
	gEnvID, uEnvID := s.activeEnvIDs(u)
	if b.ActiveEnv != nil {
		if b.ActiveEnv.GlobalEnvID != nil {
			gEnvID = b.ActiveEnv.GlobalEnvID
		}
		if b.ActiveEnv.UserEnvID != nil {
			uEnvID = b.ActiveEnv.UserEnvID
		}
	}
	values := map[string]string{}
	if gEnvID != nil {
		if e, err := s.Store.Environments.Get(*gEnvID); err == nil {
			for k, v := range parseVarsJSON(e.Vars) {
				values[k] = v
			}
		}
	}
	if uEnvID != nil {
		if e, err := s.Store.Environments.Get(*uEnvID); err == nil {
			for k, v := range parseVarsJSON(e.Vars) {
				values[k] = v
			}
		}
	}
	for k, v := range b.Vars {
		values[k] = v
	}

	// The sandbox is created lazily so a request without scripts pays nothing for
	// it, and shared between the two phases so a variable the pre-request script
	// sets is still visible to the assertions that run afterwards.
	var (
		logBuf        bytes.Buffer
		rt            *script.Runtime
		env           *script.Env
		preRan        bool
		testRan       bool
		testError     string
		scriptLogs    []string
		scriptChanged map[string]string
	)
	sandbox := func() (*script.Runtime, *script.Env) {
		if rt == nil {
			rt = script.New(script.WithTimeout(s.scriptTimeout()), script.WithConsole(&logBuf))
			env = script.NewEnv(&script.RequestCtx{
				Method:   method,
				URL:      urlStr,
				BodyType: bodyT,
				Body:     body,
				Headers:  script.SortedHeaders(headers),
			}, values)
			rt.Bind(env)
		}
		return rt, env
	}

	// Pre-request script: runs before variable resolution, so it can sign the
	// payload or rewrite the request, and so a variable it sets is visible to the
	// resolver below. Secrets are deliberately absent from the variable bag: a
	// script can only leave a {{sec.NAME}} placeholder behind for the resolver to
	// expand, never read a value.
	if strings.TrimSpace(scriptSrc) != "" {
		preRan = true
		rt, env = sandbox()
		_, serr := rt.Run("pre-request.js", scriptSrc)
		if serr != nil {
			// A script error aborts the request (like Postman): a signature that
			// was never computed must not be sent as an unsigned call.
			msg := script.ErrorMessage(serr)
			s.audit(u.Username, "execute.script_error", msg)
			if errors.Is(serr, script.ErrTimeout) {
				fail(w, http.StatusBadRequest, "script_timeout", msg)
				return
			}
			fail(w, http.StatusBadRequest, "script_error", msg)
			return
		}

		method = env.Request.Method
		urlStr = env.Request.URL
		body = env.Request.Body
		// A script that writes a body into a body_type=none request clearly wants
		// it sent; "raw" is the honest label for free-form text.
		if bodyT == "none" && strings.TrimSpace(body) != "" {
			bodyT = "raw"
		}
		headers = env.HeaderMap()
		for k, v := range env.Vars {
			values[k] = v
		}
	}

	secretLookup := func(name string) (string, bool) {
		return s.Vault.Lookup(name, func() ([]byte, error) {
			blob, found, err := s.Store.Secrets.GetByName(name)
			if err != nil || !found {
				return nil, nil
			}
			return blob, nil
		})
	}
	resolver := executor.NewResolver(values, secretLookup)

	// Resolve every text field through the same resolver.
	urlOut, _ := resolver.Resolve(urlStr)
	for k, v := range headers {
		headers[k], _ = resolver.Resolve(v)
	}
	for i, q := range query {
		query[i][0], _ = resolver.Resolve(q[0])
		query[i][1], _ = resolver.Resolve(q[1])
	}
	if bodyT != "none" {
		body, _ = resolver.Resolve(body)
		variables, _ = resolver.Resolve(variables)
	}
	// GraphQL is a body_type, not a separate method: the editor keeps the query
	// in `body` and the variables document next to it, and the wire format is
	// composed here so the executor stays a plain HTTP client.
	if bodyT == "graphql" {
		gql, err := executor.GraphQLBody(body, variables)
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		body = gql
		bodyT = "json"
	}
	warnings := resolver.Warnings()
	sort.Strings(warnings)
	if strings.Contains(urlOut, "{{") {
		fail(w, http.StatusBadRequest, "unresolved_variable",
			"url still contains placeholders after resolution: "+strings.Join(warnings, ", "))
		return
	}

	// Build the redactor as soon as secrets are resolved: every string that
	// leaves the request path (history, audit log, response) must be masked.
	redactor := executor.NewRedactor(resolver.UsedSecrets())
	safeURL := redactor.Text(urlOut)

	// Load the SSRF whitelist.
	whitelistStr := s.settingOr("ssrf_whitelist", defaultWhitelist)
	wl, err := executor.ParseWhitelist(whitelistStr)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid ssrf_whitelist setting: "+err.Error())
		return
	}

	// Load timeout ("60s", "2m" or a bare number of seconds).
	timeout := s.CFG.Timeout
	if tv := s.settingOr("exec_timeout", ""); tv != "" {
		if d, ok := parseTimeout(tv); ok {
			timeout = d
		}
	}

	// Proxy: opt-in per request, configured once by an admin. Asking for a proxy
	// that was never configured is an error rather than a silent direct call —
	// quietly ignoring the flag would hide a routing mistake.
	proxyURL := ""
	if useProxy {
		proxyURL = strings.TrimSpace(s.settingOr("proxy_url", ""))
		if proxyURL == "" {
			fail(w, http.StatusBadRequest, "proxy_not_configured",
				"this request is set to use a proxy, but no proxy_url is configured")
			return
		}
	}

	in := executor.In{
		Method: method, URL: urlOut, Headers: headers, Query: query,
		BodyType: bodyT, Body: body, Follow: b.FollowRedirects, Timeout: timeout,
		ProxyURL: proxyURL,
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout+5*time.Second)
	defer cancel()

	out, err := s.Exec.Execute(ctx, in, wl)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fail(w, http.StatusGatewayTimeout, "timeout", "request timed out")
			return
		}
		if errors.Is(err, executor.ErrSSRF) {
			s.audit(u.Username, "execute.ssrf_blocked", method+" "+safeURL+" -> "+redactor.Text(err.Error()))
			fail(w, http.StatusUnavailableForLegalReasons, "ssrf_blocked", redactor.Text(err.Error()))
			return
		}
		fail(w, http.StatusBadGateway, "upstream_error", redactor.Text(err.Error()))
		return
	}

	// Redact secrets + sensitive headers from the response and history snapshot.
	maskedHeaders := redactor.Headers(out.Headers)
	respHeaders := maskedHeaders
	redactedBody := redactor.Text(out.Body)

	// Post-response script: assertions on what came back. It sees the response
	// exactly as the caller does (secrets masked), so no assertion message can
	// carry one out. A crash here does not fail the request — it has already
	// happened — it is reported next to the response instead.
	if strings.TrimSpace(testSrc) != "" {
		testRan = true
		rt, env = sandbox()
		env.Request = &script.RequestCtx{
			Method:   method,
			URL:      safeURL,
			BodyType: bodyT,
			Body:     redactor.Text(body),
			Headers:  script.SortedHeaders(redactedRequestHeaders(redactor, headers)),
		}
		env.Response = &script.ResponseCtx{
			Code:       out.Status,
			Status:     out.StatusText,
			DurationMS: out.DurationMS,
			Body:       redactedBody,
			Headers:    maskedHeaders,
			Truncated:  out.Truncated,
			FinalURL:   redactor.Text(out.FinalURL),
		}
		rt.Bind(env)
		if _, terr := rt.Run("test.js", testSrc); terr != nil {
			testError = script.ErrorMessage(terr)
			s.audit(u.Username, "execute.test_script_error", testError)
		}
	}
	if rt != nil {
		// Captured last: the console output of both phases, in order.
		scriptLogs = scriptLogTail(logBuf.String())
		scriptChanged = env.Changed
	}

	reqSnap := redactor.RequestSnapshot(method, out.FinalURL, maskedHeaders, out.Body)
	resSnap := redactor.ResponseSnapshot(out.Status, maskedHeaders, out.HistoryBody())

	var storedReqID *int64
	if reqID != nil {
		storedReqID = reqID
	}
	if _, err := s.Store.History.Insert(
		storedReqID, u.ID, method, safeURL, out.Status, out.DurationMS, reqSnap, resSnap,
	); err != nil {
		s.Log.Warn("history insert failed", "err", err)
	}
	// The max_history setting overrides the -max-history flag when set.
	keep := s.CFG.MaxHistory
	if hv := s.settingOr("max_history", ""); hv != "" {
		if n, perr := strconv.Atoi(hv); perr == nil && n > 0 {
			keep = n
		}
	}
	if err := s.Store.History.Purge(keep); err != nil {
		s.Log.Warn("history purge failed", "err", err)
	}

	payload := map[string]any{
		"status":         out.Status,
		"status_text":    out.StatusText,
		"duration_ms":    out.DurationMS,
		"headers":        respHeaders,
		"body":           redactedBody,
		"body_truncated": out.Truncated,
		"final_url":      redactor.Text(out.FinalURL),
		"warnings":       warnings,
		// Whether this went through the proxy. The URL itself is not echoed:
		// it can carry credentials and is admin-only knowledge.
		"proxied": proxyURL != "",
	}
	if preRan || testRan {
		// Console output, the variables the scripts wrote and the pm.test results,
		// so the editor can show what happened. None of it can hold a secret:
		// scripts never see one.
		scriptOut := map[string]any{"logs": scriptLogs, "vars": scriptChanged}
		if tests := rt.Tests(); len(tests) > 0 {
			scriptOut["tests"] = tests
		}
		if testError != "" {
			scriptOut["test_error"] = testError
		}
		payload["script"] = scriptOut
	}
	ok(w, payload)
}

// redactedRequestHeaders masks what the request actually carried, so the
// post-response script can assert on the sent headers without ever seeing a
// secret value (it is handed the same text the browser gets).
func redactedRequestHeaders(redactor *executor.Redactor, headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, sensitive := executor.SensitiveHeaders[strings.ToLower(k)]; sensitive {
			out[k] = "***"
			continue
		}
		out[k] = redactor.Text(v)
	}
	return out
}

// scriptTimeout is the configured pre-request script budget.
func (s *Server) scriptTimeout() time.Duration {
	if s.CFG.ScriptTimeout > 0 {
		return s.CFG.ScriptTimeout
	}
	return defaultScriptTimeout
}

// scriptLogTail trims captured console output to the last few lines/bytes, so a
// script that logs in a loop cannot bloat the execute response.
func scriptLogTail(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > maxScriptLogLines {
		dropped := len(lines) - maxScriptLogLines
		lines = append([]string{"... " + strconv.Itoa(dropped) + " earlier lines dropped ..."},
			lines[len(lines)-maxScriptLogLines:]...)
	}
	total := 0
	for i := len(lines) - 1; i >= 0; i-- {
		total += len(lines[i]) + 1
		if total > maxScriptLogBytes {
			return append([]string{"... output truncated ..."}, lines[i+1:]...)
		}
	}
	return lines
}

// settingOr returns the settings value or fallback.
func (s *Server) settingOr(key, fallback string) string {
	if v, found, _ := s.Store.Settings.Get(key); found && v != "" {
		return v
	}
	return fallback
}
