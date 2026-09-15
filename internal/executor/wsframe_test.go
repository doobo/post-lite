package executor

import (
	"bufio"
	"net"
	"testing"
	"time"
)

func TestWSAcceptKeyVector(t *testing.T) {
	if got := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept = %q", got)
	}
}

func TestWSFrameRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	ca := &WSConn{conn: a, reader: bufio.NewReader(a)}
	cb := &WSConn{conn: b, reader: bufio.NewReader(b)}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	done := make(chan string, 1)
	go func() {
		msg, err := cb.ReadMessage()
		if err != nil {
			t.Errorf("ReadMessage: %v", err)
			return
		}
		done <- msg
	}()
	if err := ca.WriteMessage("hello ws"); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	select {
	case got := <-done:
		if got != "hello ws" {
			t.Fatalf("round trip = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame round trip timed out")
	}
}

func TestParseSSEEventJoinsData(t *testing.T) {
	ev := ParseSSEEvent("event: msg\ndata: a\ndata: b\nid: 7")
	if ev.Type != "msg" || ev.Data != "a\nb" || ev.ID != "7" {
		t.Fatalf("event = %+v", ev)
	}
	if ev := ParseSSEEvent(":comment\ndata: x"); ev.Data != "x" {
		t.Fatalf("comment line not dropped: %+v", ev)
	}
}

func TestParseRealtimeTargetMapsSchemes(t *testing.T) {
	u, err := parseRealtimeTarget("ws://10.0.0.1/chat")
	if err != nil {
		t.Fatalf("ws target: %v", err)
	}
	if u.Scheme != "http" {
		t.Fatalf("scheme = %q, want http", u.Scheme)
	}
	if _, err := parseRealtimeTarget("ftp://10.0.0.1/x"); err == nil {
		t.Fatal("ftp accepted, want rejection")
	}
}
