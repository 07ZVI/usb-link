package remoteupdate

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stage must persist a verified body in an administrator-only directory. Apply
// accepts only the returned opaque ID, never a path or command from the client.
type Server struct {
	Version, Token string
	Key            ed25519.PublicKey
	Stage          func(Manifest, io.Reader) (string, error)
	Apply          func(string) error
	Status         func() any
	Diagnostics    func() any
	RecoveryTest   func() error
	Resilient      func() bool
	Cancel         func(string) error
	Performance    http.Handler
	// Only the fixed guard controls may run while a guarded persistence retry
	// owns this slot. The handler still performs its strict kind/nonce checks.
	PersistenceRecovery http.Handler
	mu                  sync.Mutex
	staging             bool
	job                 string
	applying            bool
	cancelling          bool
	controlling         bool
	retrying            bool
	protected           atomic.Bool
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.TLS == nil || r.Header.Get("Origin") != "" || len(s.Token) < 40 || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		http.Error(w, "authentication required", 403)
		return
	}
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	if r.Method == "GET" && r.URL.Path == "/v1/status" {
		response := map[string]any{"version": s.Version, "update": s.Status()}
		if s.Diagnostics != nil {
			response["diagnostics"] = s.Diagnostics()
		}
		reply(response)
		return
	}
	protected := s.protocolProtection()
	if r.Method == "POST" && r.URL.Path == "/v1/performance" && s.Performance != nil {
		s.mu.Lock()
		recovering := protected && s.retrying && s.job != "" && s.PersistenceRecovery != nil
		if s.staging || s.applying || s.cancelling || s.controlling || s.job != "" && !recovering {
			s.mu.Unlock()
			http.Error(w, "update pending", 409)
			return
		}
		if !protected {
			// Preserve legacy lock/queue behavior when this API has never admitted
			// the experiment; old guarded callbacks keep the protected branch sticky.
			defer s.mu.Unlock()
			s.Performance.ServeHTTP(w, r)
			return
		}
		// Reserve the control slot without holding the API mutex across a
		// manager callback; expired approval callbacks use the reverse lock order.
		s.controlling = true
		s.mu.Unlock()
		if recovering {
			s.PersistenceRecovery.ServeHTTP(w, r)
		} else {
			s.Performance.ServeHTTP(w, r)
		}
		s.mu.Lock()
		s.controlling = false
		s.mu.Unlock()
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/recovery-test" && s.RecoveryTest != nil {
		if r.ContentLength != 0 || r.URL.RawQuery != "" {
			http.Error(w, "empty recovery test request required", 400)
			return
		}
		s.mu.Lock()
		if s.staging || s.applying || s.cancelling || s.controlling || s.job != "" {
			s.mu.Unlock()
			http.Error(w, "update pending", 409)
			return
		}
		if !protected {
			defer s.mu.Unlock()
			if err := s.RecoveryTest(); err != nil {
				http.Error(w, err.Error(), 409)
				return
			}
			reply(map[string]any{"status": "recovery_test_requested", "maximum_recovery_seconds": 45})
			return
		}
		s.controlling = true
		s.mu.Unlock()
		err := s.RecoveryTest()
		s.mu.Lock()
		s.controlling = false
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		reply(map[string]any{"status": "recovery_test_requested", "maximum_recovery_seconds": 45})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/prepare" {
		b, e := base64.StdEncoding.DecodeString(r.Header.Get("X-Suhang-Release"))
		if e != nil {
			http.Error(w, "invalid manifest", 400)
			return
		}
		m, e := Decode(b)
		if e != nil || m.Verify(s.Key, s.Version, time.Now()) != nil || r.ContentLength != m.Bytes {
			http.Error(w, "signed newer release required", 400)
			return
		}
		s.mu.Lock()
		if s.staging || s.applying || s.cancelling || s.controlling || s.job != "" {
			s.mu.Unlock()
			http.Error(w, "another update is pending", 409)
			return
		}
		s.staging = true
		s.mu.Unlock()
		var id string
		var eStage error
		if s.Resilient != nil && s.Resilient() && r.Context().Err() != nil {
			eStage = r.Context().Err()
		} else {
			id, eStage = s.Stage(m, http.MaxBytesReader(w, r.Body, m.Bytes))
		}
		e = eStage
		if e == nil && s.Resilient != nil && s.Resilient() && (id == "" || r.Context().Err() != nil) {
			e = fmt.Errorf("staging cancelled or returned empty job")
			if id != "" && s.Cancel != nil {
				if cancelErr := s.Cancel(id); cancelErr != nil {
					e = RetainJobError(cancelErr)
				}
			}
		}
		s.mu.Lock()
		s.staging = false
		if e == nil || id != "" && IsRetainedJobError(e) && protected {
			s.job = id
			s.retrying = e != nil
		}
		s.mu.Unlock()
		if e != nil {
			if id != "" && IsRetainedJobError(e) && protected {
				w.WriteHeader(422)
				reply(map[string]string{"id": id, "status": "persistence_recovery_required", "error": e.Error()})
				return
			}
			http.Error(w, "staging failed: "+e.Error(), 422)
			return
		}
		reply(map[string]string{"id": id, "version": m.Version, "status": "verified"})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/cancel" && s.Cancel != nil {
		if !protected && (s.Resilient == nil || !s.Resilient()) {
			http.NotFound(w, r)
			return
		}
		var q struct {
			ID string `json:"id"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&q) != nil || d.Decode(&extra) != io.EOF || r.URL.RawQuery != "" {
			http.Error(w, "invalid cancel request", 400)
			return
		}
		s.mu.Lock()
		if (s.Resilient == nil || !s.Resilient()) && !(protected && s.retrying) {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		if q.ID == "" || q.ID != s.job || s.staging || s.applying || s.cancelling || s.controlling {
			s.mu.Unlock()
			http.Error(w, "only owned idle staged update can be cancelled", 409)
			return
		}
		s.cancelling = true
		wasRetry := s.retrying
		s.mu.Unlock()
		err := s.Cancel(q.ID)
		s.mu.Lock()
		if err == nil && s.job == q.ID {
			s.job = ""
			s.retrying = false
		} else if err != nil && s.job == q.ID && protected && IsRetainedJobError(err) {
			s.retrying = true
		}
		s.cancelling = false
		s.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		status := "cancelled"
		if wasRetry {
			status = "persistence_recovered"
		}
		reply(map[string]string{"status": status, "id": q.ID})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/apply" {
		var q struct {
			ID string `json:"id"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		d.DisallowUnknownFields()
		e := d.Decode(&q)
		var extra any
		if e != nil || d.Decode(&extra) != io.EOF {
			http.Error(w, "invalid apply request", 400)
			return
		}
		s.mu.Lock()
		if q.ID == "" || q.ID != s.job || s.staging || s.applying || s.cancelling || s.controlling || s.retrying {
			s.mu.Unlock()
			http.Error(w, "no matching staged update", 409)
			return
		}
		s.applying = true
		s.mu.Unlock()
		if e = s.Apply(q.ID); e != nil {
			s.mu.Lock()
			if protected && s.job == q.ID && IsRetainedJobError(e) {
				s.applying, s.retrying = false, true
			} else if s.Resilient == nil || !s.Resilient() {
				s.applying = false
			} else if s.job == q.ID {
				s.applying = false
				if IsRetainedJobError(e) {
					s.retrying = true
				} else {
					s.job = ""
				}
			}
			s.mu.Unlock()
			http.Error(w, fmt.Sprint("handoff failed: ", e), 500)
			return
		}
		w.WriteHeader(202)
		reply(map[string]string{"status": "installation_pending", "id": q.ID})
		return
	}
	http.NotFound(w, r)
}

func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.job = ""
	s.applying = false
	s.retrying = false
}

// ResetOwned does not let an expired approval callback erase a later upload.
func (s *Server) ResetOwned(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" || s.job != id || s.staging {
		return false
	}
	s.job = ""
	s.applying = false
	s.retrying = false
	return true
}

// HoldOwned retires only an idle approval/failed write, preserving the exact
// job slot for authenticated cancellation. It never cancels a worker; the
// manager must prove no handoff before invoking this method.
func (s *Server) HoldOwned(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" || s.job != id || s.staging {
		return false
	}
	s.applying, s.retrying = false, true
	s.protected.Store(true)
	return true
}

// ResumeOwned is called only by the existing live manager when its TLS/raw
// listener is recreated. It cannot borrow a durable owner from another process.
func (s *Server) ResumeOwned(id string, retry bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || s.job != "" || s.staging || s.applying || s.cancelling || s.controlling {
		return false
	}
	s.job, s.retrying, s.applying = id, retry, !retry
	s.protected.Store(true)
	return true
}

// A guarded approval may outlive the experiment lease. Only APIs that have
// actually observed the guard keep callback lock-order protection afterwards.
func (s *Server) protocolProtection() bool {
	if s.Resilient != nil && s.Resilient() {
		s.protected.Store(true)
	}
	return s.protected.Load()
}
