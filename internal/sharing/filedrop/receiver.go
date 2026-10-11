// Package filedrop receives data files over an already authorized USB network.
// It never executes a file or exposes directory listings or remote commands.
package filedrop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"suhang/usbnet/internal/sharing/usbhttp"
	"sync"
	"time"
)

const MaxBytes int64 = 512 * 1024 * 1024

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,179}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Receipt struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Receiver struct {
	Discovery func() string
	Dir       string
	LocalIP   string
	PeerIP    string
	Guard     func() bool
	Share     http.Handler
	SMB       func(context.Context, net.Conn)
	Benchmark http.Handler
	Received  func(Receipt)
	busy      sync.Mutex
	mu        sync.Mutex
	closed    bool
	active    sync.WaitGroup
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		http.Error(w, "Receiver closed", 503)
		return
	}
	r.active.Add(1)
	r.mu.Unlock()
	defer r.active.Done()
	if q.URL.Path == "/maintenance/connection" {
		peer, _, err := net.SplitHostPort(q.RemoteAddr)
		if err != nil || peer != r.PeerIP || r.Guard == nil || !r.Guard() || q.Host != net.JoinHostPort(r.LocalIP, "10690") || q.Header.Get("Origin") != "" || (q.Header.Get("Sec-Fetch-Site") != "" && q.Header.Get("Sec-Fetch-Site") != "none") {
			http.Error(w, "USB peer required", 403)
			return
		}
		if q.Method != http.MethodGet {
			http.Error(w, "GET required", 405)
			return
		}
		if r.Discovery == nil {
			http.Error(w, "Developer mode unavailable", 503)
			return
		}
		invitation := r.Discovery()
		if invitation == "" || len(invitation) > 4096 || !json.Valid([]byte(invitation)) || !r.Guard() {
			http.Error(w, "Developer mode unavailable", 503)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		io.WriteString(w, invitation)
		return
	}
	if r.Benchmark != nil && strings.HasPrefix(q.URL.Path, "/speed/") {
		r.Benchmark.ServeHTTP(w, q)
		return
	}
	if r.Share != nil && (q.URL.Path == "/share" || strings.HasPrefix(q.URL.Path, "/share/")) {
		r.Share.ServeHTTP(w, q)
		return
	}
	if q.Method != "POST" || q.URL.Path != "/upload" {
		http.Error(w, "Upload only", 404)
		return
	}
	peer, _, e := net.SplitHostPort(q.RemoteAddr)
	if e != nil || peer != r.PeerIP || r.Guard == nil || !r.Guard() {
		http.Error(w, "USB peer required", 403)
		return
	}
	if !r.busy.TryLock() {
		http.Error(w, "Receiver busy", 409)
		return
	}
	defer r.busy.Unlock()
	name, expected := q.Header.Get("X-Suhang-Filename"), q.Header.Get("X-Suhang-SHA256")
	upper := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if !safeName.MatchString(name) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") || upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || regexp.MustCompile(`^(COM|LPT)[0-9]$`).MatchString(upper) || !digest.MatchString(expected) || q.ContentLength < 1 || q.ContentLength > MaxBytes {
		http.Error(w, "Invalid file metadata", 400)
		return
	}
	f, e := os.CreateTemp(r.Dir, "incoming-*.partial")
	if e != nil {
		http.Error(w, "Unable to stage file", 500)
		return
	}
	stage := f.Name()
	defer os.Remove(stage)
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, q.Body, MaxBytes))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	actual := hex.EncodeToString(h.Sum(nil))
	if e != nil || closeErr != nil || n != q.ContentLength || actual != expected {
		http.Error(w, "Incomplete file or hash mismatch", 422)
		return
	}
	if !r.Guard() {
		http.Error(w, "USB connection changed", 409)
		return
	}
	// Publish without overwriting an existing file. Unique timestamp+digest
	// names are generated locally; hard linking is an atomic no-replace commit.
	final := filepath.Join(r.Dir, fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102-150405.000000000"), actual[:12], name))
	if e = os.Link(stage, final); e != nil {
		http.Error(w, "Unable to save file without overwrite", 500)
		return
	}
	receipt := Receipt{n, actual}
	if r.Received != nil {
		r.Received(receipt)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(receipt)
}

func (r *Receiver) Start(ctx context.Context) (func(), error) {
	stop, e := usbhttp.RegisterWithBinary(ctx, net.JoinHostPort(r.LocalIP, "10690"), r.PeerIP, r, r.SMB)
	if e != nil {
		return nil, e
	}
	var once sync.Once
	done := make(chan struct{})
	closeReceiver := func() {
		once.Do(func() {
			r.mu.Lock()
			r.closed = true
			r.mu.Unlock()
			stop()
			r.active.Wait()
			close(done)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeReceiver()
		case <-done:
		}
	}()
	return closeReceiver, nil
}
