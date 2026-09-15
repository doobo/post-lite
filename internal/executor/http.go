package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes     = 10 << 20 // 10MB shown to UI
	historyBodyBytes = 1 << 20  // 1MB stored in history
	maxRedirects     = 5
)

// ErrSSRF is returned when a target resolves outside the CIDR whitelist.
var ErrSSRF = errors.New("ssrf blocked")

// In is a fully-resolved outbound request.
type In struct {
	Method   string
	URL      string
	Headers  map[string]string
	Query    [][2]string
	BodyType string
	Body     string
	Follow   bool
	Timeout  time.Duration

	// ProxyURL, when non-empty, dials through that HTTP/HTTPS proxy instead of
	// connecting directly (`http://`, `https://`, optionally with userinfo for
	// a proxy that wants credentials). Empty means a direct connection, which is
	// the default for every request.
	ProxyURL string
}

// Out is the captured (unredacted) response for the UI.
type Out struct {
	Status     int
	StatusText string
	DurationMS int64
	Headers    map[string][]string
	Body       string
	Truncated  bool
	FinalURL   string
}

// Executor runs outbound HTTP requests server-side.
type Executor struct {
	client    *http.Client
	transport *http.Transport

	// proxied holds one transport per proxy URL, so pooled connections survive
	// across requests without rebuilding a transport (and its pool) every time.
	// Only an admin can change proxy_url, so the map stays tiny.
	mu      sync.Mutex
	proxied map[string]*http.Transport
}

func NewExecutor(timeout time.Duration) *Executor {
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &Executor{
		client:    &http.Client{Transport: transport},
		transport: transport,
		proxied:   map[string]*http.Transport{},
	}
}

// transportFor returns the transport to use: the shared direct one, or a cached
// transport that tunnels through the configured proxy.
func (e *Executor) transportFor(proxyURL string) (*http.Transport, error) {
	if proxyURL == "" {
		return e.transport, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if tr, ok := e.proxied[proxyURL]; ok {
		return tr, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("bad proxy url %q: %w", proxyURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy url %q: scheme %q not supported", proxyURL, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy url %q: missing host", proxyURL)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(u),
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	e.proxied[proxyURL] = tr
	return tr, nil
}

// whitelist holds the allowed CIDRs.
type whitelist []net.IPNet

func (wl whitelist) contains(ip net.IP) bool {
	for _, c := range wl {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseWhitelist parses a comma-separated CIDR list.
func ParseWhitelist(s string) ([]net.IPNet, error) {
	var out []net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", part, err)
		}
		out = append(out, *ipnet)
	}
	return out, nil
}

// parseHTTPTarget validates the parts every mode needs: a parseable URL, only
// http/https, and a host to talk to.
func parseHTTPTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: bad url %q", ErrSSRF, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q not allowed", ErrSSRF, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: missing host", ErrSSRF)
	}
	return u, nil
}

// checkTargetFor is the policy actually applied to a request: with a proxy the
// target only has to be a well-formed http(s) URL, because the *proxy* resolves
// and reaches it — a local DNS lookup would refuse exactly the hosts a proxy
// exists to reach.
//
// That is the documented trade-off of enabling a proxy: its address is
// admin-configured, so it is trusted egress, and the CIDR whitelist keeps
// guarding direct connections only. Everything cheap still holds: http/https
// only, a real host, and a re-check on every redirect hop.
func checkTargetFor(ctx context.Context, raw string, wl whitelist, proxyURL string) error {
	if proxyURL != "" {
		_, err := parseHTTPTarget(raw)
		return err
	}
	return checkTarget(ctx, raw, wl)
}

// checkTarget enforces the SSRF policy for a direct connection: resolve the host
// and require every A/AAAA result to fall inside the whitelist.
func checkTarget(ctx context.Context, raw string, wl whitelist) error {
	u, err := parseHTTPTarget(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	// If the host is already an IP, check it directly.
	if ip := net.ParseIP(host); ip != nil {
		if !wl.contains(ip) {
			return fmt.Errorf("%w: %s outside whitelist", ErrSSRF, host)
		}
		return nil
	}
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: dns %s: %v", ErrSSRF, host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%w: no addresses for %s", ErrSSRF, host)
	}
	var bad []string
	for _, a := range addrs {
		if !wl.contains(a.IP) {
			bad = append(bad, a.IP.String())
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("%w: %s -> %s outside whitelist", ErrSSRF, host, strings.Join(bad, ","))
	}
	return nil
}

// Execute performs the request, applying SSRF checks on the initial target
// and (when following) on every redirect hop.
func (e *Executor) Execute(ctx context.Context, in In, wl whitelist) (*Out, error) {
	if in.Timeout <= 0 {
		in.Timeout = 60 * time.Second
	}
	transport, err := e.transportFor(in.ProxyURL)
	if err != nil {
		return nil, err
	}
	if err := checkTargetFor(ctx, in.URL, wl, in.ProxyURL); err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   in.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if !in.Follow {
				return http.ErrUseLastResponse
			}
			// Re-validate every redirect target.
			if err := checkTargetFor(ctx, req.URL.String(), wl, in.ProxyURL); err != nil {
				return err
			}
			return nil
		},
	}

	method := strings.ToUpper(in.Method)
	var bodyReader io.Reader
	if in.BodyType != "none" && in.Body != "" {
		bodyReader = strings.NewReader(in.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, in.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	if in.BodyType == "json" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if len(in.Query) > 0 {
		q := req.URL.Query()
		for _, kv := range in.Query {
			q.Add(kv[0], kv[1])
		}
		req.URL.RawQuery = q.Encode()
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	truncated := len(data) > maxBodyBytes
	if truncated {
		data = data[:maxBodyBytes]
	}

	out := &Out{
		Status:     resp.StatusCode,
		StatusText: resp.Status,
		DurationMS: elapsed.Milliseconds(),
		Headers:    map[string][]string{},
		Body:       string(data),
		Truncated:  truncated,
		FinalURL:   resp.Request.URL.String(),
	}
	for k, v := range resp.Header {
		out.Headers[k] = v
	}
	return out, nil
}

// HistoryBody returns the body capped to historyBodyBytes for the history row.
func (r *Out) HistoryBody() string {
	if len(r.Body) > historyBodyBytes {
		return r.Body[:historyBodyBytes]
	}
	return r.Body
}
