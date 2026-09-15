package executor

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SSEEvent struct {
	Type string
	Data string
	ID   string
}

// ParseSSEEvent parses a raw event block (lines split on \n) into an event.
// Comment lines (":...") are dropped; multiple data: lines join with \n.
func ParseSSEEvent(block string) SSEEvent {
	var ev SSEEvent
	var data []string
	for _, line := range strings.Split(block, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		name, value, _ := strings.Cut(line, ":")
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		switch strings.TrimSpace(name) {
		case "event":
			ev.Type = value
		case "data":
			data = append(data, value)
		case "id":
			ev.ID = value
		}
	}
	ev.Data = strings.Join(data, "\n")
	return ev
}

// DialSSE opens a GET with Accept: text/event-stream and calls yield for each
// event until ctx ends, the server closes, or maxEvents is reached (<=0 means
// unlimited). It reuses the HTTP SSRF policy verbatim: SSE travels over
// http/https, so no scheme mapping is needed.
func DialSSE(ctx context.Context, client *http.Client, rawURL string, headers map[string]string, query [][2]string, wl Whitelist, maxEvents int, yield func(SSEEvent) bool) error {
	u, err := parseHTTPTarget(rawURL)
	if err != nil {
		return err
	}
	if err := checkTarget(ctx, normalizeRealtimeURL(rawURL), wl); err != nil {
		// normalize is a no-op for http/https; keeps one policy entry point.
		return err
	}
	_ = u
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	for k, v := range headers {
		if strings.EqualFold(k, "Accept") {
			continue
		}
		req.Header.Set(k, v)
	}
	if len(query) > 0 {
		q := req.URL.Query()
		for _, kv := range query {
			q.Add(kv[0], kv[1])
		}
		req.URL.RawQuery = q.Encode()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sse: status %s", resp.Status)
	}
	br := bufio.NewReader(resp.Body)
	var block strings.Builder
	seen := 0
	flush := func() bool {
		if block.Len() == 0 {
			return true
		}
		ev := ParseSSEEvent(block.String())
		block.Reset()
		if ev.Data == "" && ev.Type == "" && ev.ID == "" {
			return true
		}
		seen++
		if maxEvents > 0 && seen > maxEvents {
			return false
		}
		return yield(ev)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			// EOF with a trailing block still counts as one event.
			if block.Len() > 0 {
				ev := ParseSSEEvent(block.String())
				if ev.Data != "" || ev.Type != "" {
					yield(ev)
				}
			}
			return nil
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if !flush() {
				return nil
			}
			continue
		}
		block.WriteString(line + "\n")
		// Guard: a single block larger than the WS frame cap is dropped.
		if block.Len() > wsMaxFrameBytes {
			block.Reset()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = time.Now()
	}
}

// DialSSEStream is the relay path: SSRF was already checked at ticket mint
// time with the admin whitelist; the caller passes that same whitelist so the
// dial re-validates the current DNS without a TOCTOU gap.
func DialSSEStream(ctx context.Context, rawURL string, headers map[string]string, query [][2]string, wl Whitelist, yield func(SSEEvent) bool) error {
	client := &http.Client{Timeout: 0}
	return DialSSE(ctx, client, rawURL, headers, query, wl, 0, yield)
}
