// Package throughput measures bounded HTTP/TCP payload throughput over an
// authorized USB peer. It does not execute files or claim USB PHY/UDP capacity.
package throughput

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ChunkBytes is one HTTP request's payload. Larger requests amortise the
// request round trip and JavaScript await gap that idle a stream between chunks;
// at ~1 GB/s a 4 MiB chunk lasted only ~4 ms, so those gaps capped the result.
const ChunkBytes = 16 * 1024 * 1024
const MaxDirectionBytes int64 = 16 * 1024 * 1024 * 1024

// Streams stays one below Safari/WebKit's six HTTP/1.1 connections per host so
// the concurrent RTT ping is not queued behind payload requests.
const Streams = 5

// IOBlockBytes is the per-call read/write size for payload bodies. 1 MiB keeps
// syscall counts low enough that a single Windows core is not the ceiling.
const IOBlockBytes = 1024 * 1024
const sessionLifetime = 75 * time.Second

// StallTimeout bounds how long one payload request may go without moving a
// read/write operation. Progress renews the deadline, but never beyond the
// session expiry; slow transfers can complete within that shared budget.
const StallTimeout = 10 * time.Second

type Measurement struct {
	Bytes       int64   `json:"bytes"`
	Seconds     float64 `json:"seconds"`
	Mbps        float64 `json:"mbps"`
	RTTMedianMS float64 `json:"http_rtt_median_ms"`
	RTTP95MS    float64 `json:"http_rtt_p95_ms"`
	RTTSamples  int     `json:"http_rtt_samples"`
}
type Report struct {
	Status       string      `json:"status"`
	StartedUTC   string      `json:"started_utc,omitempty"`
	CompletedUTC string      `json:"completed_utc,omitempty"`
	Method       string      `json:"method"`
	Streams      int         `json:"parallel_streams"`
	Download     Measurement `json:"windows_to_device"`
	Upload       Measurement `json:"device_to_windows"`
	IdleRTT      Measurement `json:"idle_http_rtt"`
	Error        string      `json:"error,omitempty"`
}

func (r Report) Summary() string {
	switch r.Status {
	case "complete":
		return fmt.Sprintf("Windows → 裝置 %.1f MB/s · 裝置 → Windows %.1f MB/s\nHTTP 往返 p95：空閒 %.1f / 下載 %.1f / 上傳 %.1f ms\nTCP 有效吞吐；不是 USB 協商速率，不測 UDP 丟包。", r.Download.Mbps/8, r.Upload.Mbps/8, r.IdleRTT.RTTP95MS, r.Download.RTTP95MS, r.Upload.RTTP95MS)
	case "download":
		return "正在測試 Windows → 裝置；測速進行中。"
	case "upload":
		return "正在測試裝置 → Windows；測速進行中。"
	case "failed":
		return "測試未完成：" + r.Error
	default:
		return "尚未測試。連接原生測速對端後可開始。"
	}
}

type session struct {
	ctx                                          context.Context
	cancel                                       context.CancelFunc
	id                                           string
	expires                                      time.Time
	report                                       Report
	downReserved, upReserved, downBytes, upBytes int64
	active                                       int
	upStart, upEnd                               time.Time
}
type Server struct {
	wsLatencyActive bool
	latencyMS       float64
	latencyAt       time.Time
	browserHost     string
	browserDevice   string
	nativeSeen      time.Time
	nativeClaimed   bool
	peer            string
	guard           func() bool
	token           string
	ctx             context.Context
	cancel          context.CancelFunc
	changed         func(Report)
	mu              sync.Mutex
	run             *session
	closed          bool
	active          sync.WaitGroup
	slots           chan struct{}
}

func New(ctx context.Context, peer string, guard func() bool, changed func(Report)) (*Server, error) {
	var secret [24]byte
	if _, e := rand.Read(secret[:]); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{peer: peer, guard: guard, token: hex.EncodeToString(secret[:]), ctx: ctx, cancel: cancel, changed: changed, slots: make(chan struct{}, Streams)}
	go func() {
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.mu.Lock()
				if s.run != nil && (s.run.report.Status == "download" || s.run.report.Status == "upload") && time.Now().After(s.run.expires) {
					s.run.report.Status = "failed"
					s.run.report.Error = "測速對端失去回應或測試逾時"
					s.run.cancel()
					r := s.run.report
					s.mu.Unlock()
					s.notify(r)
				} else {
					s.mu.Unlock()
				}
			}
		}
	}()
	return s, nil
}
func (s *Server) notify(r Report) {
	if s.changed != nil {
		s.changed(r)
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	var r Report
	if s.run != nil {
		r = s.run.report
		if r.Status == "download" || r.Status == "upload" {
			r.Status = "failed"
			r.Error = "USB 連線已結束"
			s.run.report = r
		}
	}
	s.mu.Unlock()
	s.cancel()
	s.active.Wait()
	if r.Status == "failed" {
		s.notify(r)
	}
}
func (s *Server) allowed(q *http.Request) bool {
	peer, _, e := net.SplitHostPort(q.RemoteAddr)
	if e != nil || peer != s.peer || s.ctx.Err() != nil || s.guard == nil || !s.guard() {
		return false
	}
	if s.browserHost != "" && (q.Host != s.browserHost || q.Header.Get("Sec-Fetch-Site") == "cross-site") {
		return false
	}
	if origin := q.Header.Get("Origin"); origin != "" && origin != "http://"+q.Host {
		return false
	}
	return true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "closed", 503)
		return
	}
	s.active.Add(1)
	s.mu.Unlock()
	defer s.active.Done()
	if !s.allowed(q) {
		http.Error(w, "authorized USB peer required", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if q.URL.Path == "/speed/" && q.Method == "GET" {
		if s.browserHost != "" {
			s.browserPage(w)
		} else {
			http.Error(w, "Use the native Windows measurement panel.", 410)
		}
		return
	}
	if q.URL.Path == "/speed/native" && q.Method == "GET" {
		if s.browserHost != "" {
			http.NotFound(w, q)
			return
		}
		s.nativePoll(w)
		return
	}
	if q.URL.Path == "/speed/ws-latency" && q.Method == "GET" {
		s.browserLatency(w, q)
		return
	}

	if q.Header.Get("X-Suhang-Test") != s.token {
		http.Error(w, "test token required", 403)
		return
	}
	if q.URL.Path == "/speed/native/start" && q.Method == "POST" {
		if s.browserHost != "" || q.Header.Get("Origin") != "" {
			http.Error(w, "native USB peer required", 403)
			return
		}
		if e := s.StartNative(); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		writeJSON(w, map[string]bool{"started": true})
		return
	}
	if q.URL.Path == "/speed/latency" && q.Method == "POST" {
		s.recordLatency(w, q)
		return
	}
	if q.URL.Path == "/speed/ping" && q.Method == "GET" {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
		return
	}
	if q.URL.Path == "/speed/start" && q.Method == "POST" {
		if s.browserHost != "" {
			s.startBrowser(w)
		} else {
			http.Error(w, "start from the native Windows UI", 403)
		}
		return
	}
	id := q.Header.Get("X-Suhang-Run")
	s.mu.Lock()
	r := s.run
	if r == nil || id != r.id || time.Now().After(r.expires) || (r.report.Status != "download" && r.report.Status != "upload") {
		s.mu.Unlock()
		http.Error(w, "test session expired", 409)
		return
	}
	s.mu.Unlock()
	switch {
	case q.URL.Path == "/speed/down" && q.Method == "GET":
		s.transfer(w, q, r, false)
	case q.URL.Path == "/speed/up" && q.Method == "POST":
		s.transfer(w, q, r, true)
	case q.URL.Path == "/speed/finish" && q.Method == "POST":
		s.finish(w, q, r)
	case q.URL.Path == "/speed/cancel" && q.Method == "POST":
		s.mu.Lock()
		r.report.Status = "failed"
		r.report.Error = "使用者取消測試"
		r.cancel()
		report := r.report
		s.mu.Unlock()
		s.notify(report)
		writeJSON(w, report)
	default:
		http.NotFound(w, q)
	}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// progressReader renews the connection's read deadline after every read, so
// the deadline limits a stall rather than the duration of the whole chunk.
type progressReader struct {
	io.Reader
	renew func() error
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.Reader.Read(b)
	if n > 0 && err == nil {
		err = p.renew()
	}
	return n, err
}

// deadlineErr ignores writers that cannot hold deadlines, as the fixed
// deadline did before; any other failure ends the request.
func deadlineErr(err error) error {
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

// uploadSink hides io.Discard's ReaderFrom: io.CopyBuffer would otherwise ignore
// the supplied IOBlockBytes buffer and read the request body in 8 KiB pieces.
type uploadSink struct{}

func (uploadSink) Write(p []byte) (int, error) { return len(p), nil }

// Share the non-ReaderFrom sink with the native download path so CopyBuffer
// actually uses the requested block size in both directions.
func discardPayload(r io.Reader) (int64, error) {
	return io.CopyBuffer(uploadSink{}, r, make([]byte, IOBlockBytes))
}

func (s *Server) transfer(w http.ResponseWriter, q *http.Request, r *session, up bool) {
	// A browser can consume the final TCP bytes before the sending handler
	// retires. Queue the replacement briefly rather than rejecting the extra stream.
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-q.Context().Done():
		return
	case <-r.ctx.Done():
		return
	case <-timer.C:
		http.Error(w, "test streams busy", 429)
		return
	}
	s.mu.Lock()
	expected := "download"
	reserved := &r.downReserved
	if up {
		expected = "upload"
		reserved = &r.upReserved
	}
	if s.run != r || r.ctx.Err() != nil || time.Now().After(r.expires) || r.report.Status != expected || *reserved+ChunkBytes > MaxDirectionBytes {
		s.mu.Unlock()
		http.Error(w, "test limit or phase mismatch", 409)
		return
	}
	if up && q.ContentLength != ChunkBytes {
		s.mu.Unlock()
		http.Error(w, "invalid chunk size", 400)
		return
	}
	*reserved += ChunkBytes
	r.active++
	if up && r.upStart.IsZero() {
		r.upStart = time.Now()
	}
	s.mu.Unlock()
	var count int64
	var err error
	controller := http.NewResponseController(w)
	// Serialize renewal with cancellation: a late renewal must never undo the
	// immediate deadline that wakes a blocked read/write on cancel or expiry.
	var deadlineMu sync.Mutex
	renew := func() error {
		deadlineMu.Lock()
		defer deadlineMu.Unlock()
		if err := r.ctx.Err(); err != nil {
			return err
		}
		if err := q.Context().Err(); err != nil {
			return err
		}
		deadline := time.Now().Add(StallTimeout)
		if deadline.After(r.expires) {
			deadline = r.expires
		}
		if up {
			return deadlineErr(controller.SetReadDeadline(deadline))
		}
		return deadlineErr(controller.SetWriteDeadline(deadline))
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(r.ctx, func() {
		defer close(interrupted)
		deadlineMu.Lock()
		defer deadlineMu.Unlock()
		if up {
			controller.SetReadDeadline(time.Now())
		} else {
			controller.SetWriteDeadline(time.Now())
		}
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		if up {
			controller.SetReadDeadline(time.Time{})
		} else {
			controller.SetWriteDeadline(time.Time{})
		}
	}()
	if up {
		if err = renew(); err == nil {
			count, err = io.CopyBuffer(uploadSink{}, progressReader{http.MaxBytesReader(w, q.Body, ChunkBytes), renew}, make([]byte, IOBlockBytes))
		}
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(ChunkBytes))
		block := make([]byte, IOBlockBytes)
		for count < ChunkBytes && err == nil {
			if s.ctx.Err() != nil || q.Context().Err() != nil {
				err = context.Canceled
				break
			}
			// Renewed per block: the limit is a stall of StallTimeout, not the whole chunk's duration.
			if err = renew(); err != nil {
				break
			}
			var n int
			n, err = w.Write(block)
			count += int64(n)
			if n != len(block) && err == nil {
				err = io.ErrShortWrite
			}
		}
	}
	s.mu.Lock()
	r.active--
	if err == nil && count == ChunkBytes && r.ctx.Err() == nil && time.Now().Before(r.expires) {
		if up {
			r.upBytes += count
			r.upEnd = time.Now()
		} else {
			r.downBytes += count
		}
	} else {
		if err == nil {
			err = r.ctx.Err()
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
		}
		if r.report.Status != "failed" {
			r.report.Status = "failed"
			if errors.Is(r.ctx.Err(), context.DeadlineExceeded) || !time.Now().Before(r.expires) {
				r.report.Error = "測速對端失去回應或測試逾時"
			} else {
				r.report.Error = "測試資料傳輸中斷"
			}
		}
		r.cancel()
	}
	report := r.report
	s.mu.Unlock()
	if err != nil || count != ChunkBytes {
		s.notify(report)
		if up {
			http.Error(w, "incomplete test data", 422)
		}
		return
	}
	if up {
		writeJSON(w, map[string]int64{"bytes": count})
	}
}

type finishRequest struct {
	Direction string    `json:"direction"`
	Bytes     int64     `json:"bytes"`
	Seconds   float64   `json:"seconds"`
	RTT       []float64 `json:"rtt"`
	Idle      []float64 `json:"idle"`
}

func latency(samples []float64) (Measurement, error) {
	var m Measurement
	// Allow RTT sampling throughout the 75-second budget (one ping per 180ms).
	if len(samples) > 512 {
		return m, fmt.Errorf("too many latency samples")
	}
	values := append([]float64(nil), samples...)
	for _, n := range values {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 15000 {
			return m, fmt.Errorf("invalid latency")
		}
	}
	sort.Float64s(values)
	m.RTTSamples = len(values)
	if len(values) > 0 {
		m.RTTMedianMS = values[(len(values)-1)/2]
		m.RTTP95MS = values[int(math.Ceil(float64(len(values))*.95))-1]
	}
	return m, nil
}
func (s *Server) finish(w http.ResponseWriter, q *http.Request, r *session) {
	var v finishRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, q.Body, 16384))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&v); e != nil {
		http.Error(w, "invalid report", 400)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "trailing report data", 400)
		return
	}
	m, e := latency(v.RTT)
	idle, ie := latency(v.Idle)
	if e != nil || ie != nil || v.Seconds <= 0 || v.Seconds > sessionLifetime.Seconds() || math.IsNaN(v.Seconds) || math.IsInf(v.Seconds, 0) {
		http.Error(w, "invalid measurement", 400)
		return
	}
	s.mu.Lock()
	if r.ctx.Err() != nil || time.Now().After(r.expires) || r.active != 0 || r.report.Status != v.Direction || v.Bytes <= 0 || v.Bytes > MaxDirectionBytes {
		s.mu.Unlock()
		http.Error(w, "test not ready", 409)
		return
	}
	if (v.Direction == "download" && v.Bytes != r.downBytes) || (v.Direction == "upload" && v.Bytes != r.upBytes) {
		s.mu.Unlock()
		http.Error(w, "receiver byte count mismatch", 409)
		return
	}
	m.Bytes = v.Bytes
	m.Seconds = v.Seconds
	if v.Direction == "upload" {
		m.Seconds = r.upEnd.Sub(r.upStart).Seconds()
	}
	if m.Seconds <= 0 {
		s.mu.Unlock()
		http.Error(w, "invalid timing", 400)
		return
	}
	m.Mbps = float64(m.Bytes) * 8 / m.Seconds / 1e6
	if v.Direction == "download" {
		r.report.Download = m
		r.report.IdleRTT = idle
		r.report.Status = "upload"
	} else {
		r.report.Upload = m
		r.report.Status = "complete"
		r.report.CompletedUTC = time.Now().UTC().Format(time.RFC3339)
		r.cancel()
	}
	report := r.report
	s.mu.Unlock()
	s.notify(report)
	writeJSON(w, report)
}
