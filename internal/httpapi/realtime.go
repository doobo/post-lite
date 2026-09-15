package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"postlite/internal/executor"
	"postlite/internal/models"
	"postlite/internal/repository"
)

// Realtime relay: the browser never dials the target itself (same rule as
// POST /api/execute). A ticket carries the resolved upstream so the URL —
// which may embed {{sec.NAME}} output — never appears in access logs:
//
//	POST /api/realtime/connect {protocol,url,headers,query,...} -> {ticket}
//	GET  /api/realtime/ws?ticket=..   (WebSocket upgrade, bidirectional pump)
//	GET  /api/realtime/sse?ticket=..  (text/event-stream, upstream -> browser)
//
// WS idle timeout 300s and 1MB/frame match DESIGN V0.2; history stores a
// redacted summary (frame/event counts + first bytes), not the full stream.

const (
	realtimeTicketTTL = 60 * time.Second
	realtimeIdle      = 300 * time.Second
	realtimeMaxLog    = 8 << 10 // 8KB summary per direction in history
)

type realtimeTicket struct {
	protocol string // ws | sse
	url      string // resolved upstream URL
	headers  map[string]string
	query    [][2]string
	// WS subprotocols offered by the editor (upstream negotiation).
	protocols []string
	// SSE event-type filter from the editor (empty = all).
	eventType string
	user      models.User
	safeURL   string
	redactor  *executor.Redactor
	whitelist executor.Whitelist
	expires   time.Time
}

var (
	rtMu      sync.Mutex
	rtTickets = map[string]*realtimeTicket{}
)

func mintTicket(t *realtimeTicket) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	t.expires = time.Now().Add(realtimeTicketTTL)
	rtMu.Lock()
	rtTickets[id] = t
	// Opportunistic expiry sweep so the map cannot grow on ticket spam.
	for k, v := range rtTickets {
		if time.Now().After(v.expires) {
			delete(rtTickets, k)
		}
	}
	rtMu.Unlock()
	return id
}

func takeTicket(id string) (*realtimeTicket, bool) {
	rtMu.Lock()
	defer rtMu.Unlock()
	t, ok := rtTickets[id]
	if !ok {
		return nil, false
	}
	delete(rtTickets, id)
	if time.Now().After(t.expires) {
		return nil, false
	}
	return t, true
}

type realtimeConnectBody struct {
	Protocol  string            `json:"protocol"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Query     []kvPair          `json:"query"`
	Protocols []string          `json:"protocols"`
	EventType string            `json:"event_type"`
	RequestID *int64            `json:"request_id"`
	Vars      map[string]string `json:"vars"`
	ActiveEnv *activateBody     `json:"active_env"`
}

func (s *Server) realtimeConnect(w http.ResponseWriter, r *http.Request) {
	u, okd := s.requireUser(w, r)
	if !okd {
		return
	}
	var b realtimeConnectBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.Protocol != "ws" && b.Protocol != "sse" {
		fail(w, http.StatusBadRequest, "bad_request", "protocol must be ws or sse")
		return
	}
	var (
		urlStr    string
		headers   = map[string]string{}
		query     [][2]string
		protocols []string
		event     string
	)
	if b.RequestID != nil {
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
		urlStr = rq.URL
		event = rq.Variables
		p := requestPayloadOf(rq)
		headers = p.HeadersMap()
		query = p.QueryPairs()
		protocols = splitProtocols(rq.Body)
	} else {
		urlStr = b.URL
		headers = b.Headers
		event = b.EventType
		protocols = b.Protocols
		for _, q := range b.Query {
			query = append(query, [2]string{q.K, q.V})
		}
		if urlStr == "" {
			fail(w, http.StatusBadRequest, "bad_request", "url is required")
			return
		}
	}

	// Same resolver precedence as execute: global -> user -> vars + secrets.
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
	urlOut, _ := resolver.Resolve(urlStr)
	for k, v := range headers {
		headers[k], _ = resolver.Resolve(v)
	}
	for i, q := range query {
		query[i][0], _ = resolver.Resolve(q[0])
		query[i][1], _ = resolver.Resolve(q[1])
	}
	for i, p := range protocols {
		protocols[i], _ = resolver.Resolve(p)
	}
	event, _ = resolver.Resolve(event)
	warnings := resolver.Warnings()
	sort.Strings(warnings)
	if strings.Contains(urlOut, "{{") {
		fail(w, http.StatusBadRequest, "unresolved_variable",
			"url still contains placeholders: "+strings.Join(warnings, ", "))
		return
	}
	redactor := executor.NewRedactor(resolver.UsedSecrets())
	safeURL := redactor.Text(urlOut)

	// SSRF now, not on upgrade: a ticket for an outside host must never exist.
	wl, err := executor.ParseWhitelist(s.settingOr("ssrf_whitelist", defaultWhitelist))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid ssrf_whitelist: "+err.Error())
		return
	}
	if b.Protocol == "ws" {
		if err := checkRealtimeTarget(urlOut, wl); err != nil {
			s.audit(u.Username, "realtime.ssrf_blocked", "ws "+safeURL)
			fail(w, http.StatusUnavailableForLegalReasons, "ssrf_blocked", redactor.Text(err.Error()))
			return
		}
	} else {
		if _, err := executor.ParseWhitelistCheck(urlOut, wl); err != nil {
			s.audit(u.Username, "realtime.ssrf_blocked", "sse "+safeURL)
			fail(w, http.StatusUnavailableForLegalReasons, "ssrf_blocked", redactor.Text(err.Error()))
			return
		}
	}

	ticket := mintTicket(&realtimeTicket{
		protocol: b.Protocol, url: urlOut, headers: headers, query: query,
		protocols: protocols, eventType: event, user: u,
		safeURL: safeURL, redactor: redactor, whitelist: wl,
	})
	ok(w, map[string]any{"ticket": ticket, "warnings": warnings})
}

// checkRealtimeTarget enforces the CIDR whitelist on ws/wss by mapping them
// to http/https first; proxy is intentionally unsupported in V1.
func checkRealtimeTarget(raw string, wl executor.Whitelist) error {
	return executor.CheckRealtimeTarget(raw, wl)
}

func (s *Server) realtimeWS(w http.ResponseWriter, r *http.Request) {
	t, ok := takeTicket(r.URL.Query().Get("ticket"))
	if !ok || t.protocol != "ws" {
		fail(w, http.StatusBadRequest, "bad_request", "invalid or expired ticket")
		return
	}
	down, err := executor.ServeWS(w, r)
	if err != nil {
		return // ServeWS already wrote the HTTP error.
	}
	defer down.Close()
	up, err := executor.DialWS(t.url, t.headers, t.protocols, 15*time.Second)
	if err != nil {
		_ = down.WriteText("upstream dial failed: "+t.redactor.Text(err.Error()), false)
		s.writeRealtimeHistory(t, "WS", 502, 0, nil, "dial: "+t.redactor.Text(err.Error()))
		_ = down.Close()
		return
	}
	defer up.Close()
	start := time.Now()
	var (
		upCount, downCount int
		upLog, downLog     strings.Builder
	)
	_ = down.SetDeadline(time.Now().Add(realtimeIdle))
	_ = up.SetDeadline(time.Now().Add(realtimeIdle))
	errCh := make(chan error, 2)
	// browser -> upstream
	go func() {
		for {
			msg, err := down.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			downCount++
			if downLog.Len() < realtimeMaxLog {
				fmt.Fprintf(&downLog, "[%d] %s\n", downCount, truncateLine(msg, 500))
			}
			_ = up.SetDeadline(time.Now().Add(realtimeIdle))
			if err := up.WriteMessage(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()
	// upstream -> browser
	go func() {
		for {
			msg, err := up.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			upCount++
			red := t.redactor.Text(msg)
			if upLog.Len() < realtimeMaxLog {
				fmt.Fprintf(&upLog, "[%d] %s\n", upCount, truncateLine(red, 500))
			}
			_ = down.SetDeadline(time.Now().Add(realtimeIdle))
			if err := down.WriteText(red, false); err != nil {
				errCh <- err
				return
			}
		}
	}()
	<-errCh
	dur := time.Since(start).Milliseconds()
	summary := fmt.Sprintf("ws frames up=%d down=%d subprotocol=%s\n-- to upstream --\n%s\n-- from upstream --\n%s",
		downCount, upCount, up.Subprotocol, t.redactor.Text(downLog.String()), upLog.String())
	s.writeRealtimeHistory(t, "WS", 101, dur, nil, summary)
}

func (s *Server) realtimeSSE(w http.ResponseWriter, r *http.Request) {
	t, ok := takeTicket(r.URL.Query().Get("ticket"))
	if !ok || t.protocol != "sse" {
		fail(w, http.StatusBadRequest, "bad_request", "invalid or expired ticket")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)

	start := time.Now()
	count := 0
	var log strings.Builder
	ctx := r.Context()
	yield := func(ev executor.SSEEvent) bool {
		if t.eventType != "" && ev.Type != "" && ev.Type != t.eventType {
			return true
		}
		count++
		red := t.redactor.Text(ev.Data)
		if log.Len() < realtimeMaxLog {
			fmt.Fprintf(&log, "[%d] event=%s id=%s %s\n", count, ev.Type, ev.ID, truncateLine(red, 500))
		}
		if fl != nil {
			if ev.Type != "" {
				fmt.Fprintf(w, "event: %s\n", ev.Type)
			}
			if ev.ID != "" {
				fmt.Fprintf(w, "id: %s\n", ev.ID)
			}
			for _, line := range strings.Split(red, "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprintf(w, "\n")
			fl.Flush()
		}
		return true
	}
	err := executor.DialSSEStream(ctx, t.url, t.headers, t.query, t.whitelist, yield)
	dur := time.Since(start).Milliseconds()
	status := 200
	body := log.String()
	if err != nil && ctx.Err() == nil {
		status = 502
		body = "upstream: " + t.redactor.Text(err.Error()) + "\n" + body
		if fl != nil {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", t.redactor.Text(err.Error()))
			fl.Flush()
		}
	}
	s.writeRealtimeHistory(t, "SSE", status, dur, nil, body)
}

func (s *Server) writeRealtimeHistory(t *realtimeTicket, method string, status int, durMS int64, _ []string, summary string) {
	reqSnap := t.redactor.Text(method + " " + t.safeURL)
	if len(summary) > 1<<20 {
		summary = summary[:1<<20]
	}
	if _, err := s.Store.History.Insert(nil, t.user.ID, method, t.safeURL, status, durMS, reqSnap, summary); err != nil {
		s.Log.Warn("realtime history insert failed", "err", err)
	}
	keep := s.CFG.MaxHistory
	if hv := s.settingOr("max_history", ""); hv != "" {
		var n int
		if _, err := fmt.Sscanf(hv, "%d", &n); err == nil && n > 0 {
			keep = n
		}
	}
	_ = s.Store.History.Purge(keep)
}

func truncateLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func splitProtocols(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(body, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// requestPayloadOf adapts a stored request to the payload helpers so realtime
// connect reuses the same header/query JSON parsing as execute.
func requestPayloadOf(rq *models.Request) repository.RequestPayload {
	return repository.RequestPayload{Headers: rq.Headers, Query: rq.Query}
}
