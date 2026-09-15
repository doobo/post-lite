package executor

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	wsMaxFrameBytes = 1 << 20 // 1MB per message, matches DESIGN V0.2
	wsGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// WSConn is a minimal RFC6455 connection shared by the upstream client
// (postlite -> target) and the downstream server (browser -> postlite).
// Client frames are masked, server frames are not; read handles both.
type WSConn struct {
	conn   net.Conn
	reader *bufio.Reader

	writeMu sync.Mutex

	// negotiated subprotocol, empty when none.
	Subprotocol string
}

// wsAcceptKey derives Sec-WebSocket-Accept from the client key.
func wsAcceptKey(key string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsNewKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// dialTLSWithDialer dials TCP then upgrades to TLS (used for wss). The proxy
// case is intentionally unsupported in V1: realtime goes direct so the CIDR
// whitelist keeps guarding it; proxied WS arrives with Socket.IO later.
func dialTLSWithDialer(dialer *net.Dialer, host string, timeout time.Duration) (net.Conn, error) {
	raw, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	serverName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: serverName})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// DialWS opens a client connection to a ws/wss (or http/https, treated as
// ws/wss) URL. Headers are sent on the handshake; protocols, when non-empty,
// negotiates Sec-WebSocket-Protocol. The caller owns SSRF: pass the already
// validated URL.
func DialWS(rawURL string, headers map[string]string, protocols []string, timeout time.Duration) (*WSConn, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	// Accept http/https as aliases so callers can store one URL form.
	lowered := rawURL
	u, err := parseRealtimeTarget(rawURL)
	if err != nil {
		return nil, err
	}
	isTLS := u.Scheme == "https"
	// Rebuild the ws(s) URL for the request line: keep path+query.
	scheme := "ws"
	if isTLS {
		scheme = "wss"
	}
	host := u.Host
	if u.Port() == "" {
		if isTLS {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	_ = lowered

	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if isTLS {
		conn, err = dialTLSWithDialer(dialer, host, timeout)
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	key, err := wsNewKey()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	path := u.RequestURI()
	var sb strings.Builder
	sb.WriteString("GET " + path + " HTTP/1.1\r\n")
	sb.WriteString("Host: " + u.Host + "\r\n")
	sb.WriteString("Upgrade: websocket\r\n")
	sb.WriteString("Connection: Upgrade\r\n")
	sb.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	sb.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range headers {
		lk := strings.ToLower(k)
		// These are managed by the handshake itself.
		if lk == "host" || lk == "upgrade" || lk == "connection" ||
			lk == "sec-websocket-key" || lk == "sec-websocket-version" ||
			lk == "sec-websocket-protocol" || lk == "content-length" {
			continue
		}
		sb.WriteString(k + ": " + v + "\r\n")
	}
	if len(protocols) > 0 {
		sb.WriteString("Sec-WebSocket-Protocol: " + strings.Join(protocols, ", ") + "\r\n")
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = scheme
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake: %w", err)
	}
	defer func() {
		// Drain nothing: the body must be empty on 101; close it anyway.
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake: status %s", resp.Status)
	}
	if accept := resp.Header.Get("Sec-WebSocket-Accept"); accept != wsAcceptKey(key) {
		_ = conn.Close()
		return nil, errors.New("websocket handshake: bad accept key")
	}
	_ = conn.SetDeadline(time.Time{})

	return &WSConn{conn: conn, reader: br, Subprotocol: resp.Header.Get("Sec-WebSocket-Protocol")}, nil
}

// ServeWS upgrades a browser GET to a server-side WSConn. It validates the
// mandatory handshake headers and answers 101, then pumps unmasked frames
// downstream. The caller must have authenticated (session middleware) before
// calling: the browser cannot set auth headers on a WebSocket handshake,
// cookies are the only credential in flight.
func ServeWS(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("websocket: method must be GET")
	}
	if !headerHasToken(r.Header.Get("Connection"), "upgrade") ||
		strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("websocket: not an upgrade request")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "unsupported websocket version", http.StatusBadRequest)
		return nil, errors.New("websocket: unsupported version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing websocket key", http.StatusBadRequest)
		return nil, errors.New("websocket: missing key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return nil, errors.New("websocket: hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		// Echo the first offered subprotocol, like a minimal server.
		first := strings.TrimSpace(strings.Split(proto, ",")[0])
		resp += "Sec-WebSocket-Protocol: " + first + "\r\n"
	}
	resp += "\r\n"
	if _, err := io.WriteString(rw, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sub := ""
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		sub = strings.TrimSpace(strings.Split(proto, ",")[0])
	}
	return &WSConn{conn: conn, reader: rw.Reader, Subprotocol: sub}, nil
}

func headerHasToken(h, tok string) bool {
	for _, part := range strings.Split(h, ",") {
		if strings.EqualFold(strings.TrimSpace(part), tok) {
			return true
		}
	}
	return false
}

// WriteText sends one masked (client) or unmasked (server) text frame.
// isClient selects masking: upstream dial uses true, downstream serve uses false.
func (c *WSConn) WriteText(payload string, isClient bool) error {
	return c.writeFrame(0x1, []byte(payload), isClient)
}

// WriteMessage sends a text frame as a client (masked). Upstream path only.
func (c *WSConn) WriteMessage(payload string) error {
	return c.writeFrame(0x1, []byte(payload), true)
}

func (c *WSConn) writeFrame(opcode byte, payload []byte, mask bool) error {
	if len(payload) > wsMaxFrameBytes {
		return fmt.Errorf("websocket: message %d bytes exceeds %d", len(payload), wsMaxFrameBytes)
	}
	var hdr [14]byte
	hdr[0] = 0x80 | (opcode & 0x0F)
	n := 2
	var maskKey [4]byte
	if mask {
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}
	}
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
		if mask {
			hdr[1] |= 0x80
		}
	case len(payload) < 65536:
		hdr[1] = 126
		if mask {
			hdr[1] |= 0x80
		}
		hdr[2] = byte(len(payload) >> 8)
		hdr[3] = byte(len(payload))
		n = 4
	default:
		hdr[1] = 127
		if mask {
			hdr[1] |= 0x80
		}
		l := uint64(len(payload))
		for i := 0; i < 8; i++ {
			hdr[2+i] = byte(l >> (56 - 8*i))
		}
		n = 10
	}
	if mask {
		copy(hdr[n:], maskKey[:])
		n += 4
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(hdr[:n]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	if !mask {
		_, err := c.conn.Write(payload)
		return err
	}
	// Mask in place on a copy so the caller buffer is untouched.
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}
	_, err := c.conn.Write(masked)
	return err
}

// ReadMessage returns the next complete text/binary message, transparently
// handling fragmentation and answering pings with pongs. Close frames are
// surfaced as io.EOF so pump loops terminate cleanly. Both masked (browser)
// and unmasked (upstream) frames are accepted.
func (c *WSConn) ReadMessage() (string, error) {
	var msg []byte
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return "", err
		}
		switch opcode {
		case 0x0: // continuation
			msg = append(msg, payload...)
			if fin {
				return string(msg), nil
			}
		case 0x1, 0x2: // text / binary
			msg = append(msg, payload...)
			if fin {
				return string(msg), nil
			}
		case 0x8: // close
			_ = c.writeFrame(0x8, nil, false)
			return "", io.EOF
		case 0x9: // ping -> pong
			_ = c.writeFrame(0xA, payload, false)
		case 0xA: // pong, ignore
		default:
			return "", fmt.Errorf("websocket: unknown opcode %d", opcode)
		}
		if len(msg) > wsMaxFrameBytes {
			return "", fmt.Errorf("websocket: message exceeds %d", wsMaxFrameBytes)
		}
	}
}

func (c *WSConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.reader, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := int64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.reader, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = 0
		for i := 0; i < 8; i++ {
			length = length<<8 | int64(ext[i])
		}
	}
	if length > wsMaxFrameBytes {
		return false, 0, nil, fmt.Errorf("websocket: frame %d bytes exceeds %d", length, wsMaxFrameBytes)
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return false, 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	}
	return fin, opcode, payload, nil
}

// Close sends a close frame (best effort) and closes the TCP connection.
func (c *WSConn) Close() error {
	_ = c.writeFrame(0x8, nil, false)
	return c.conn.Close()
}

// SetDeadline proxies to the underlying connection for idle-timeout pumps.
func (c *WSConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
