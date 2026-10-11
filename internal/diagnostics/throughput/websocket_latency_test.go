package throughput

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/websocket"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestWebSocketEchoRequiresTokenAndEndsWithSession(t *testing.T) {
	s, _ := NewBrowser(context.Background(), "127.0.0.1", "temporary", func() bool { return true }, nil)
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	u, _ := url.Parse(httpServer.URL)
	s.browserHost = u.Host
	dial := func() *websocket.Conn {
		ws, e := websocket.Dial("ws://"+u.Host+"/speed/ws-latency", "", httpServer.URL)
		if e != nil {
			t.Fatal(e)
		}
		ws.SetDeadline(time.Now().Add(3 * time.Second))
		return ws
	}
	bad := dial()
	websocket.Message.Send(bad, "authorize:wrong")
	var r string
	if websocket.Message.Receive(bad, &r) == nil {
		t.Fatal("wrong token accepted")
	}
	bad.Close()
	ws := dial()
	defer ws.Close()
	if e := websocket.Message.Send(ws, "authorize:"+s.token); e != nil {
		t.Fatal(e)
	}
	if e := websocket.Message.Receive(ws, &r); e != nil || r != "ready" {
		t.Fatal(r, e)
	}
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b, 5)
	copy(b[4:12], "USBLWS01")
	if e := websocket.Message.Send(ws, b); e != nil {
		t.Fatal(e)
	}
	var echoed []byte
	if e := websocket.Message.Receive(ws, &echoed); e != nil || len(echoed) != 64 || binary.BigEndian.Uint32(echoed) != 5 {
		t.Fatal(e, echoed)
	}
	ended := make(chan struct{})
	go func() { s.Close(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for lingering WebSocket")
	}
	if e := websocket.Message.Receive(ws, &echoed); e == nil {
		t.Fatal("echo survived session close")
	}
}
func TestWebSocketUnavailableToForeignOriginAndMac(t *testing.T) {
	for _, browser := range []bool{false, true} {
		s, _ := New(context.Background(), "10.6.9.3", func() bool { return true }, nil)
		if browser {
			s.browserHost = "10.6.9.1:10690"
		}
		q := httptest.NewRequest("GET", "http://10.6.9.1:10690/speed/ws-latency", nil)
		q.RemoteAddr = "10.6.9.3:40000"
		q.Header.Set("Origin", "http://evil.invalid")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		s.Close()
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}
