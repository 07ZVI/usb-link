package throughput

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrowserPeerOriginTokenAndNativeSeparation(t *testing.T) {
	s, e := NewBrowser(context.Background(), "10.6.9.2", "10.6.9.1:10690", func() bool { return true }, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	call := func(method, path, host, peer, origin, token string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://"+host+path, nil)
		q.RemoteAddr = peer + ":5000"
		q.Header.Set("Origin", origin)
		q.Header.Set("X-Suhang-Test", token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		return w
	}
	w := call("GET", "/speed/", "10.6.9.1:10690", "10.6.9.2", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "iPad 測速") || strings.Contains(w.Body.String(), "__CONFIG__") {
		t.Fatal("page not rendered")
	}
	for _, c := range []struct{ host, peer, origin string }{{"evil.test", "10.6.9.2", ""}, {"10.6.9.1:10690", "192.168.1.4", ""}, {"10.6.9.1:10690", "10.6.9.2", "https://evil.test"}} {
		if call("GET", "/speed/", c.host, c.peer, c.origin, "").Code != 403 {
			t.Fatal("unauthorized browser allowed")
		}
	}
	if call("POST", "/speed/start", "10.6.9.1:10690", "10.6.9.2", "", "").Code != 403 {
		t.Fatal("token missing accepted")
	}
	w = call("POST", "/speed/start", "10.6.9.1:10690", "10.6.9.2", "", s.token)
	var v NativeCommand
	json.Unmarshal(w.Body.Bytes(), &v)
	if w.Code != 200 || v.ID == "" {
		t.Fatal("browser start failed")
	}
	if call("POST", "/speed/start", "10.6.9.1:10690", "10.6.9.2", "", s.token).Code != 409 {
		t.Fatal("overlap allowed")
	}
	if call("GET", "/speed/native", "10.6.9.1:10690", "10.6.9.2", "", "").Code != 404 {
		t.Fatal("iPad accepted native polling")
	}
	if s.StartNative() == nil {
		t.Fatal("iPad accepted Windows native start")
	}
	mac, _ := NewBrowserForDevice(context.Background(), "Mac", "10.6.9.2", "10.6.9.1:10690", func() bool { return true }, nil)
	defer mac.Close()
	for _, peer := range []string{"10.6.9.2", "10.6.9.3", "192.168.1.4"} {
		q := httptest.NewRequest("GET", "http://10.6.9.1:10690/speed/", nil)
		q.RemoteAddr = peer + ":5000"
		w = httptest.NewRecorder()
		mac.ServeHTTP(w, q)
		if peer == "10.6.9.2" {
			if w.Code != 200 || !strings.Contains(w.Body.String(), "Windows → Mac") || strings.Contains(w.Body.String(), "iPad") || strings.Contains(w.Body.String(), "__DEVICE__") {
				t.Fatal("Mac page mislabeled or incomplete")
			}
		} else if w.Code != 403 {
			t.Fatal("another peer reached the Mac test")
		}
	}
	if mac.StartNative() == nil {
		t.Fatal("Mac browser session accepted native start")
	}
	if _, e := NewBrowserForDevice(context.Background(), "<script>", "10.6.9.2", "10.6.9.1:10690", func() bool { return true }, nil); e == nil {
		t.Fatal("unknown device accepted")
	}
	if ready, _, _ := mac.MeasurementState(); ready {
		t.Fatal("page GET must not claim live browser heartbeat")
	}
	q := httptest.NewRequest("POST", "http://10.6.9.1:10690/speed/latency", strings.NewReader(`{"ms":1.25}`))
	q.RemoteAddr = "10.6.9.2:5000"
	q.Header.Set("X-Suhang-Test", mac.token)
	w = httptest.NewRecorder()
	mac.ServeHTTP(w, q)
	if ready, _, _ := mac.MeasurementState(); !ready {
		t.Fatal("browser readback not observed")
	}
	if ready, _, _ := mac.NativeState(); ready {
		t.Fatal("browser readback confused with native poll")
	}
	mac.mu.Lock()
	mac.latencyAt = mac.latencyAt.Add(-10 * time.Second)
	mac.mu.Unlock()
	if ready, _, _ := mac.MeasurementState(); ready {
		t.Fatal("stale browser heartbeat retained")
	}

}

func TestLatencyFreshnessAndValidation(t *testing.T) {
	s, _ := New(context.Background(), "10.6.9.2", func() bool { return true }, nil)
	defer s.Close()
	if _, ok := s.LiveLatency(); ok {
		t.Fatal("invented initial latency")
	}
	for _, tc := range []struct {
		body string
		code int
	}{{`{"ms":1.25}`, 200}, {`{"ms":-1}`, 400}, {`{"ms":16000}`, 400}, {`{"ms":1} {}`, 400}} {
		q := httptest.NewRequest("POST", "http://10.6.9.1:10690/speed/latency", strings.NewReader(tc.body))
		q.RemoteAddr = "10.6.9.2:4444"
		q.Header.Set("X-Suhang-Test", s.token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, q)
		if w.Code != tc.code {
			t.Fatalf("%s: %d", tc.body, w.Code)
		}
	}
	if ms, ok := s.LiveLatency(); !ok || ms != 1.25 {
		t.Fatal("latency not retained")
	}
	s.mu.Lock()
	s.latencyAt = s.latencyAt.Add(-10 * time.Second)
	s.mu.Unlock()
	if _, ok := s.LiveLatency(); ok {
		t.Fatal("stale latency shown as live")
	}
}
