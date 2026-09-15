package httpapi

import (
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
		UseProxy  bool   `json:"use_proxy"`
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

	ok(w, map[string]any{
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
	})
}

// settingOr returns the settings value or fallback.
func (s *Server) settingOr(key, fallback string) string {
	if v, found, _ := s.Store.Settings.Get(key); found && v != "" {
		return v
	}
	return fallback
}
