package usbhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func endpoint(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func client(peer string) *http.Client {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peer)}}).DialContext}}
	return c
}
func expect(t *testing.T, peer, a string, code int, body string) {
	t.Helper()
	// macOS has no 127.0.0.2 alias by default. Exercise peer dispatch with a
	// request fixture while the real socket remains open, without adding aliases.
	registry.Lock()
	l := registry.listeners[a]
	registry.Unlock()
	if l == nil {
		t.Fatal("listener missing")
	}
	q := httptest.NewRequest("GET", "http://"+a+"/maintenance/connection", nil)
	q.RemoteAddr = peer + ":12345"
	w := httptest.NewRecorder()
	l.server.Handler.ServeHTTP(w, q)
	if w.Code != code || (body != "" && w.Body.String() != body) {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
}

func TestTwoOwnersRouteAndDetachIndependently(t *testing.T) {
	a := endpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mac, e := Register(ctx, a, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mac") }))
	if e != nil {
		t.Fatal(e)
	}
	defer mac()
	ipad, e := Register(ctx, a, "127.0.0.2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	if e != nil {
		t.Fatal(e)
	}
	defer ipad()
	if _, e = Register(ctx, a, "127.0.0.1", http.NotFoundHandler()); e == nil {
		t.Fatal("duplicate owner accepted")
	}
	real, e := client("127.0.0.1").Get("http://" + a)
	if e != nil {
		t.Fatal(e)
	}
	real.Body.Close()
	expect(t, "127.0.0.1", a, 200, "mac")
	expect(t, "127.0.0.2", a, 404, "")
	expect(t, "127.0.0.3", a, 403, "")
	mac()
	expect(t, "127.0.0.1", a, 403, "")
	expect(t, "127.0.0.2", a, 404, "")
	mac2, e := Register(ctx, a, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mac2") }))
	if e != nil {
		t.Fatal(e)
	}
	expect(t, "127.0.0.1", a, 200, "mac2")
	ipad()
	expect(t, "127.0.0.1", a, 200, "mac2")
	mac2()
	l, e := net.Listen("tcp4", a)
	if e != nil {
		t.Fatal("last owner left listener", e)
	}
	l.Close()
}
func TestOwnerCancellationDrainsOnlyItsRequest(t *testing.T) {
	a := endpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	left := make(chan struct{})
	stop, e := Register(ctx, a, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(left) }))
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	other, e := Register(context.Background(), a, "127.0.0.2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "alive") }))
	if e != nil {
		t.Fatal(e)
	}
	defer other()
	requestClient := client("127.0.0.1")
	go func() {
		r, _ := requestClient.Get("http://" + a)
		if r != nil {
			r.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	stop()
	select {
	case <-left:
	case <-time.After(2 * time.Second):
		t.Fatal("owner did not drain")
	}
	expect(t, "127.0.0.2", a, 200, "alive")
}
