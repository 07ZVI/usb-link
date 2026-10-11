package filedrop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func upload(r *Receiver, name string, body []byte) *httptest.ResponseRecorder {
	q := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	q.RemoteAddr = "10.77.0.1:55555"
	q.Header.Set("X-Suhang-Filename", name)
	h := sha256.Sum256(body)
	q.Header.Set("X-Suhang-SHA256", hex.EncodeToString(h[:]))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}

func TestFilesAreHashVerifiedDataAndNeverOverwrite(t *testing.T) {
	dir := t.TempDir()
	r := &Receiver{Dir: dir, PeerIP: "10.77.0.1", Guard: func() bool { return true }}
	var receipts atomic.Int32
	r.Received = func(v Receipt) {
		if v.Bytes != 5 {
			t.Error("wrong bytes")
		}
		receipts.Add(1)
	}
	for i := 0; i < 2; i++ {
		if w := upload(r, "setup.exe", []byte("hello")); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 2 || receipts.Load() != 2 {
		t.Fatal("overwritten or missing receipt")
	}
	for _, f := range files {
		b, e := os.ReadFile(filepath.Join(dir, f.Name()))
		if e != nil || string(b) != "hello" || strings.HasSuffix(f.Name(), ".partial") {
			t.Fatal("invalid committed data")
		}
	}
}

func TestUnrelatedPeerInvalidMetadataAndChangedUSBLeaveNoFile(t *testing.T) {
	for _, problem := range []string{"peer", "guard", "hash", "length", "oversize", "../setup.exe", "CON.txt", "LPT1.exe", "bad:", "end.", "end "} {
		t.Run(problem, func(t *testing.T) {
			dir := t.TempDir()
			calls := 0
			r := &Receiver{Dir: dir, PeerIP: "10.77.0.1", Guard: func() bool { calls++; return problem != "guard" || calls == 1 }}
			body := []byte("hello")
			q := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
			q.RemoteAddr = "10.77.0.1:42"
			h := sha256.Sum256(body)
			q.Header.Set("X-Suhang-Filename", "setup.exe")
			q.Header.Set("X-Suhang-SHA256", hex.EncodeToString(h[:]))
			switch problem {
			case "peer":
				q.RemoteAddr = "192.168.0.1:42"
			case "hash":
				q.Header.Set("X-Suhang-SHA256", strings.Repeat("0", 64))
			case "length":
				q.ContentLength = 6
			case "oversize":
				q.ContentLength = MaxBytes + 1
			case "guard":
			default:
				q.Header.Set("X-Suhang-Filename", problem)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, q)
			if w.Code == 200 {
				t.Fatal("unqualified upload accepted")
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatal("failed upload left data", files)
			}
		})
	}
}

func TestOnlyOneUploadAndClosedReceiverRejectsRequests(t *testing.T) {
	r := &Receiver{Dir: t.TempDir(), PeerIP: "10.77.0.1", Guard: func() bool { return true }}
	pr, pw := io.Pipe()
	entered := make(chan struct{})
	q := httptest.NewRequest("POST", "/upload", &startedReader{pr, entered, false})
	q.RemoteAddr = "10.77.0.1:42"
	q.ContentLength = 5
	q.Header.Set("X-Suhang-Filename", "setup.exe")
	h := sha256.Sum256([]byte("hello"))
	q.Header.Set("X-Suhang-SHA256", hex.EncodeToString(h[:]))
	done := make(chan struct{})
	go func() { defer close(done); r.ServeHTTP(httptest.NewRecorder(), q) }()
	<-entered
	if w := upload(r, "second.exe", []byte("hello")); w.Code != 409 {
		t.Fatal("parallel upload accepted", w.Code)
	}
	pw.Write([]byte("hello"))
	pw.Close()
	<-done
	pr.Close()
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.active.Wait()
	if w := upload(r, "third.exe", []byte("hello")); w.Code != 503 {
		t.Fatal("closed receiver accepted file")
	}
}

type startedReader struct {
	io.Reader
	entered chan struct{}
	started bool
}

func (r *startedReader) Read(b []byte) (int, error) {
	if !r.started {
		r.started = true
		close(r.entered)
	}
	return r.Reader.Read(b)
}

func TestDeveloperDiscoveryUSBOnly(t *testing.T) {
	r := &Receiver{LocalIP: "10.6.9.1", PeerIP: "10.6.9.2", Guard: func() bool { return true }, Discovery: func() string { return `{"token":"private-test-token"}` }}
	for _, tc := range []struct {
		name, peer, host, method, origin, site string
		enabled                                bool
		want                                   int
	}{
		{"usb", "10.6.9.2:50000", "10.6.9.1:10690", "GET", "", "", true, 200},
		{"lan", "192.168.1.2:50000", "10.6.9.1:10690", "GET", "", "", true, 403},
		{"host", "10.6.9.2:50000", "evil.invalid", "GET", "", "", true, 403},
		{"browser", "10.6.9.2:50000", "10.6.9.1:10690", "GET", "https://evil.invalid", "", true, 403},
		{"cross-site", "10.6.9.2:50000", "10.6.9.1:10690", "GET", "", "cross-site", true, 403},
		{"post", "10.6.9.2:50000", "10.6.9.1:10690", "POST", "", "", true, 405},
		{"disabled", "10.6.9.2:50000", "10.6.9.1:10690", "GET", "", "", false, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.Discovery = func() string {
				if !tc.enabled {
					return ""
				}
				return `{"token":"private-test-token"}`
			}
			q := httptest.NewRequest(tc.method, "http://10.6.9.1:10690/maintenance/connection", nil)
			q.RemoteAddr = tc.peer
			q.Host = tc.host
			q.Header.Set("Origin", tc.origin)
			q.Header.Set("Sec-Fetch-Site", tc.site)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, q)
			if w.Code != tc.want {
				t.Fatalf("status %d", w.Code)
			}
			if tc.want != 200 && strings.Contains(w.Body.String(), "private-test-token") {
				t.Fatal("credential leaked")
			}
			if tc.want == 200 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("discovery must not cache")
			}
		})
	}
	r.Guard = func() bool { return false }
	q := httptest.NewRequest("GET", "http://10.6.9.1:10690/maintenance/connection", nil)
	q.RemoteAddr = "10.6.9.2:50000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	if w.Code != 403 {
		t.Fatal("detached USB accepted")
	}
}
