package throughput

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	s, e := New(context.Background(), "127.0.0.1", func() bool { return true }, nil)
	if e != nil {
		t.Fatal(e)
	}
	h := httptest.NewServer(s)
	t.Cleanup(func() { h.Close(); s.Close() })
	return s, h, h.Client()
}
func request(t *testing.T, s *Server, c *http.Client, base, method, path, id string, body io.Reader) *http.Response {
	t.Helper()
	q, e := http.NewRequest(method, base+path, body)
	if e != nil {
		t.Fatal(e)
	}
	q.Header.Set("X-Suhang-Test", s.token)
	q.Header.Set("X-Suhang-Run", id)
	v, e := c.Do(q)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func startTest(t *testing.T, s *Server, h *httptest.Server, c *http.Client) string {
	v := request(t, s, c, h.URL, "GET", "/speed/native", "", nil)
	io.Copy(io.Discard, v.Body)
	v.Body.Close()
	if e := s.StartNative(); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.run.id
}
func TestRealHTTPBidirectionalByteAccounting(t *testing.T) {
	s, h, c := fixture(t)
	id := startTest(t, s, h, c)
	for i := 0; i < 2; i++ {
		v := request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
		n, e := io.Copy(io.Discard, v.Body)
		v.Body.Close()
		if e != nil || n != ChunkBytes || v.StatusCode != 200 {
			t.Fatal(n, e, v.Status)
		}
	}
	finish := func(direction string, n int64) Report {
		b, _ := json.Marshal(finishRequest{Direction: direction, Bytes: n, Seconds: .1, RTT: []float64{1, 2, 3, 9}, Idle: []float64{1, 2}})
		v := request(t, s, c, h.URL, "POST", "/speed/finish", id, bytes.NewReader(b))
		defer v.Body.Close()
		var r Report
		json.NewDecoder(v.Body).Decode(&r)
		if v.StatusCode != 200 {
			t.Fatal(v.Status, r)
		}
		return r
	}
	r := finish("download", 2*ChunkBytes)
	if r.Status != "upload" || r.Download.Mbps <= 0 || r.Download.RTTP95MS != 9 {
		t.Fatal(r)
	}
	v := request(t, s, c, h.URL, "POST", "/speed/up", id, bytes.NewReader(make([]byte, ChunkBytes)))
	io.Copy(io.Discard, v.Body)
	v.Body.Close()
	if v.StatusCode != 200 {
		t.Fatal(v.Status)
	}
	r = finish("upload", ChunkBytes)
	if r.Status != "complete" || r.Upload.Mbps <= 0 || r.Upload.Seconds == .1 {
		t.Fatal("upload must use server receive timing", r)
	}
	v = request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
	v.Body.Close()
	if v.StatusCode != 409 {
		t.Fatal("completed run reused")
	}
}
func TestAuthOriginBoundsAndWrongCounts(t *testing.T) {
	s, h, c := fixture(t)
	for _, tc := range []struct{ token, origin, peer string }{{"bad", "", "127.0.0.1:1"}, {s.token, "http://evil.invalid", "127.0.0.1:1"}, {s.token, "", "10.6.9.3:1"}} {
		q := httptest.NewRequest("POST", "http://10.6.9.1:47773/speed/start", nil)
		q.RemoteAddr = tc.peer
		q.Header.Set("X-Suhang-Test", tc.token)
		q.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	id := startTest(t, s, h, c)
	v := request(t, s, c, h.URL, "POST", "/speed/start", "", nil)
	v.Body.Close()
	if v.StatusCode != 403 {
		t.Fatal("peer must not start tests")
	}
	v = request(t, s, c, h.URL, "POST", "/speed/finish", id, strings.NewReader(`{"direction":"download","bytes":1,"seconds":1}`))
	v.Body.Close()
	if v.StatusCode != 409 {
		t.Fatal("invented received bytes accepted")
	}
	s.mu.Lock()
	s.run.downReserved = MaxDirectionBytes
	s.mu.Unlock()
	v = request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
	v.Body.Close()
	if v.StatusCode != 409 {
		t.Fatal("byte limit ignored")
	}
	s.mu.Lock()
	s.run.expires = time.Now().Add(-time.Second)
	s.mu.Unlock()
	v = request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
	v.Body.Close()
	if v.StatusCode != 409 {
		t.Fatal("expiry ignored")
	}
}
func TestCancellationRevokesRunAndAllowsAnother(t *testing.T) {
	s, h, c := fixture(t)
	id := startTest(t, s, h, c)
	v := request(t, s, c, h.URL, "POST", "/speed/cancel", id, nil)
	v.Body.Close()
	v = request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
	v.Body.Close()
	if v.StatusCode != 409 {
		t.Fatal("canceled run accepted")
	}
	if startTest(t, s, h, c) == id {
		t.Fatal("run nonce reused")
	}
}
func TestConcurrentChunksRaceFree(t *testing.T) {
	s, h, c := fixture(t)
	id := startTest(t, s, h, c)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
			io.Copy(io.Discard, v.Body)
			v.Body.Close()
		}()
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run.downBytes != 4*ChunkBytes || s.run.active != 0 {
		t.Fatal(s.run.downBytes, s.run.active)
	}
}

// Simulate four completed TCP responses whose handlers have not yet retired.
// A browser's replacement request should wait, not fail with a spurious 409.
func TestReplacementStreamWaitsForRetiringHandler(t *testing.T) {
	s, h, c := fixture(t)
	id := startTest(t, s, h, c)
	for i := 0; i < Streams; i++ {
		s.slots <- struct{}{}
	}
	done := make(chan int, 1)
	go func() {
		v := request(t, s, c, h.URL, "GET", "/speed/down", id, nil)
		io.Copy(io.Discard, v.Body)
		v.Body.Close()
		done <- v.StatusCode
	}()
	select {
	case status := <-done:
		t.Fatalf("replacement rejected before slot retired: %d", status)
	case <-time.After(50 * time.Millisecond):
	}
	<-s.slots
	select {
	case status := <-done:
		if status != 200 {
			t.Fatal(status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement did not resume")
	}
	for i := 1; i < Streams; i++ {
		<-s.slots
	}
}

func TestNativePeerCannotStartWithoutWindowsAction(t *testing.T) {
	s, h, c := fixture(t)
	client := NativeClient{HTTP: c, Base: h.URL}
	v, e := client.Poll(context.Background())
	if e != nil || v.ID != "" {
		t.Fatal(v, e)
	}
	ready, busy, _ := s.NativeState()
	if !ready || busy {
		t.Fatal("poll must only announce readiness")
	}
	r := request(t, s, c, h.URL, "POST", "/speed/start", "", nil)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("peer started a test")
	}
	if e = s.StartNative(); e != nil {
		t.Fatal(e)
	}
	v, e = client.Poll(context.Background())
	if e != nil || v.ID == "" {
		t.Fatal(v, e)
	}
	s.CancelNative()
	r = request(t, s, c, h.URL, "GET", "/speed/down", v.ID, nil)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("cancel did not revoke data")
	}
}

func TestNativeClientCompletesBothDirections(t *testing.T) {
	s, h, c := fixture(t)
	client := NativeClient{HTTP: c, Base: h.URL}
	if _, e := client.Poll(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := s.StartNative(); e != nil {
		t.Fatal(e)
	}
	v, e := client.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	report, e := client.Run(context.Background(), v)
	if e != nil {
		t.Fatal(e)
	}
	if report.Status != "complete" || report.Download.Bytes == 0 || report.Upload.Bytes == 0 || report.Download.Mbps <= 0 || report.Upload.Mbps <= 0 {
		t.Fatal(report)
	}
	t.Logf("native loopback only: down %.1f, up %.1f Mbps", report.Download.Mbps, report.Upload.Mbps)
}

func TestNativePeerCanStartButBrowserAndWrongTokenCannot(t *testing.T) {
	s, h, c := fixture(t)
	client := NativeClient{HTTP: c, Base: h.URL}
	v, e := client.Poll(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	bad := v
	bad.Token = "wrong"
	if client.Start(context.Background(), bad) == nil {
		t.Fatal("wrong token started test")
	}
	q, _ := http.NewRequest("POST", h.URL+"/speed/native/start", nil)
	q.Header.Set("X-Suhang-Test", v.Token)
	q.Header.Set("Origin", h.URL)
	r, e := c.Do(q)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("browser started native test")
	}
	if e := client.Start(context.Background(), v); e != nil {
		t.Fatal(e)
	}
	_, busy, _ := s.NativeState()
	if !busy {
		t.Fatal("no native test started")
	}
	if e := client.Start(context.Background(), v); e == nil {
		t.Fatal("duplicate start accepted")
	}
	s.CancelNative()
}

func TestConcurrentDeviceTestsDoNotReplaceOrCancelEachOther(t *testing.T) {
	mac, mh, mc := fixture(t)
	ipad, _, _ := fixture(t)
	SetDeviceCurrent("Mac", mac)
	SetDeviceCurrent("iPad", ipad)
	defer func() { SetDeviceCurrent("Mac", nil); SetDeviceCurrent("iPad", nil) }()
	_ = startTest(t, mac, mh, mc)
	if DeviceCurrent("Mac") != mac || DeviceCurrent("iPad") != ipad {
		t.Fatal("device server overwritten")
	}
	DeviceCurrent("iPad").CancelNative()
	_, busy, _ := mac.NativeState()
	if !busy {
		t.Fatal("iPad cancellation stopped Mac test")
	}
	ipad.Close()
	_, busy, _ = mac.NativeState()
	if !busy {
		t.Fatal("iPad disconnection stopped Mac test")
	}
	mac.CancelNative()
}
