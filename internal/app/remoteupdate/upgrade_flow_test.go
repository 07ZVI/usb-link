package remoteupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// This models the reported sequence through the production HTTP handler, byte
// verifier and queue-admission policy; no Windows or hardware stub can turn a
// corrupt upload or a live USB action into an accepted signed upgrade.
func TestQueuedAfterOldCleanupFailureCanUpgradeAndRetryWithoutErasingRecovery(t *testing.T) {
	key, m, body := signed(t)
	manifest, _ := json.Marshal(m)
	durable := "owned-recovery-receipt-and-user-choice"
	pending, busy, reserved := true, false, false
	counter := 0
	job, status := "", ""
	failApply := false
	var cancelDuringUpload context.CancelFunc
	stages, applies := 0, 0
	s := &Server{Version: "0.7.7", Token: string(bytes.Repeat([]byte{'a'}, 64)), Key: key, Resilient: func() bool { return true }, Status: func() any { return status }}
	s.Stage = func(g Manifest, r io.Reader) (string, error) {
		stages++
		cancel, _, ok := ReserveIdleActions(pending, busy, false, false, false, reserved)
		if !ok {
			return "", fmt.Errorf("actual task owns USB")
		}
		if cancel {
			pending = false
		}
		reserved = true
		if err := VerifyBinary(r, g); err != nil {
			reserved = false
			return "", err
		}
		counter++
		job = fmt.Sprintf("%032x", counter)
		status = "staged"
		if cancelDuringUpload != nil {
			cancelDuringUpload()
		}
		return job, nil
	}
	s.Cancel = func(id string) error {
		if id != job || status != "staged" {
			return fmt.Errorf("not owned idle stage")
		}
		status = "cancelled"
		reserved = false
		return nil
	}
	s.Apply = func(id string) error {
		applies++
		if id != job || !reserved {
			return fmt.Errorf("reservation changed")
		}
		if failApply {
			status = "failed"
			reserved = false
			return fmt.Errorf("verified handoff failed")
		}
		status = "handoff"
		return nil
	}
	request := func(path string, payload []byte, ctx context.Context) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "https://10.6.9.1"+path, bytes.NewReader(payload))
		r.TLS = &tls.ConnectionState{}
		if ctx != nil {
			r = r.WithContext(ctx)
		}
		r.Header.Set("Authorization", "Bearer "+s.Token)
		if path == "/v1/prepare" {
			r.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(manifest))
			r.ContentLength = m.Bytes
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	want := func(path string, payload []byte, code int) {
		t.Helper()
		w := request(path, payload, nil)
		if w.Code != code {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	// Old cleanup stopped the queue consumer. Preparing an upgrade cancels only
	// that unconsumed request; truncated/corrupt uploads still release the lease.
	want("/v1/prepare", body[:len(body)/2], 422)
	if pending || reserved || durable != "owned-recovery-receipt-and-user-choice" {
		t.Fatal("queue cancellation touched durable recovery or retained ownership")
	}
	want("/v1/prepare", bytes.Repeat([]byte{9}, len(body)), 422)
	if reserved || applies != 0 {
		t.Fatal("corrupt bytes executed or blocked retry")
	}
	busy = true
	want("/v1/prepare", body, 422)
	busy = false
	want("/v1/prepare", body, 200)
	first := job
	want("/v1/prepare", body, 409)
	want("/v1/cancel", []byte(`{"id":"not-owned"}`), 409)
	want("/v1/cancel", []byte(fmt.Sprintf(`{"id":%q}`, first)), 200)
	if reserved || status != "cancelled" {
		t.Fatal("cancel did not release owned stage")
	}
	// Request cancellation after durable staging must cancel the exact stage,
	// then allow a new request rather than retaining a hidden pending job.
	ctx, cancel := context.WithCancel(context.Background())
	cancelDuringUpload = cancel
	if w := request("/v1/prepare", body, ctx); w.Code != 422 {
		t.Fatal(w.Code)
	}
	cancelDuringUpload = nil
	if reserved || status != "cancelled" {
		t.Fatal("cancelled upload retained reservation")
	}
	want("/v1/prepare", body, 200)
	failed := job
	failApply = true
	want("/v1/apply", []byte(fmt.Sprintf(`{"id":%q}`, failed)), 500)
	if reserved || status != "failed" {
		t.Fatal("failed handoff retained ownership")
	}
	failApply = false
	want("/v1/prepare", body, 200)
	latest := job
	if s.ResetOwned(failed) {
		t.Fatal("expired callback reset the newer upload")
	}
	want("/v1/apply", []byte(fmt.Sprintf(`{"id":%q}`, latest)), 202)
	want("/v1/apply", []byte(fmt.Sprintf(`{"id":%q}`, latest)), 409)
	want("/v1/cancel", []byte(fmt.Sprintf(`{"id":%q}`, latest)), 409)
	if !reserved || status != "handoff" || applies != 2 || stages != 7 || durable != "owned-recovery-receipt-and-user-choice" {
		t.Fatalf("final ownership/evidence changed: %v %s applies=%d stages=%d", reserved, status, applies, stages)
	}
}

func TestResilienceIsDefaultOffAndCannotWeakenAuthentication(t *testing.T) {
	key, m, body := signed(t)
	data, _ := json.Marshal(m)
	calls := 0
	s := &Server{Version: "0.7.7", Token: string(bytes.Repeat([]byte{'a'}, 64)), Key: key, Status: func() any { return "idle" }, Cancel: func(string) error { calls++; return nil }}
	for _, tlsOn := range []bool{false, true} {
		r := httptest.NewRequest("POST", "https://10.6.9.1/v1/cancel", bytes.NewBufferString(`{"id":"x"}`))
		r.TLS = nil
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+s.Token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		want := 403
		if tlsOn {
			want = 404
		}
		if w.Code != want || calls != 0 {
			t.Fatal("default-off cancellation exposed", w.Code)
		}
	}
	s.Resilient = func() bool { return true }
	s.Stage = func(Manifest, io.Reader) (string, error) { calls++; return "x", nil }
	r := httptest.NewRequest("POST", "https://10.6.9.1/v1/prepare", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer bad")
	r.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(data))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 || calls != 0 {
		t.Fatal("experiment bypassed TLS token verification")
	}
}

func TestExpiredApprovalCannotDeadlockCurrentCancellationOrAdmitConcurrentApply(t *testing.T) {
	key, m, body := signed(t)
	data, _ := json.Marshal(m)
	s := &Server{Version: "0.7.7", Token: string(bytes.Repeat([]byte{'a'}, 64)), Key: key, Resilient: func() bool { return true }, job: "current"}
	var manager sync.Mutex
	managerHeld := make(chan struct{})
	cancelEntered := make(chan struct{})
	allowLateReset := make(chan struct{})
	lateDone := make(chan struct{})
	go func() {
		manager.Lock()
		close(managerHeld)
		<-allowLateReset
		s.ResetOwned("expired")
		manager.Unlock()
		close(lateDone)
	}()
	<-managerHeld
	s.Cancel = func(id string) error {
		close(cancelEntered)
		manager.Lock()
		defer manager.Unlock()
		if id != "current" {
			return fmt.Errorf("wrong owner")
		}
		return nil
	}
	s.Apply = func(string) error { t.Error("apply started during owned cancellation"); return nil }
	s.Stage = func(g Manifest, r io.Reader) (string, error) {
		if err := VerifyBinary(r, g); err != nil {
			return "", err
		}
		return "later", nil
	}
	req := func(path, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://10.6.9.1"+path, bytes.NewBufferString(payload))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+s.Token)
		if path == "/v1/prepare" {
			r.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(data))
			r.ContentLength = m.Bytes
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	cancelDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { cancelDone <- req("/v1/cancel", `{"id":"current"}`) }()
	select {
	case <-cancelEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel callback did not enter")
	}
	if got := req("/v1/apply", `{"id":"current"}`); got.Code != 409 {
		t.Fatal("cancellation did not reserve apply slot", got.Code)
	}
	if got := req("/v1/prepare", string(body)); got.Code != 409 {
		t.Fatal("new upload entered during cancellation", got.Code)
	}
	close(allowLateReset)
	select {
	case <-lateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("expired manager callback deadlocked with current cancel")
	}
	select {
	case got := <-cancelDone:
		if got.Code != 200 {
			t.Fatal(got.Code, got.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("current cancellation did not finish")
	}
	if got := req("/v1/prepare", string(body)); got.Code != 200 {
		t.Fatal("cancel did not release stage slot", got.Code)
	}
	if s.ResetOwned("current") {
		t.Fatal("old cancellation cleared later upload")
	}
}

func TestControlLockSemanticsRemainLegacyUntilGuardObserved(t *testing.T) {
	enabled := false
	s := &Server{Token: string(bytes.Repeat([]byte{'a'}, 64)), Resilient: func() bool { return enabled }}
	wantFree := false
	calls := 0
	s.Performance = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		free := s.mu.TryLock()
		if free {
			s.mu.Unlock()
		}
		if free != wantFree {
			t.Errorf("callback mutex free=%v want=%v", free, wantFree)
		}
		w.WriteHeader(204)
	})
	request := func() {
		r := httptest.NewRequest("POST", "https://10.6.9.1/v1/performance", nil)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+s.Token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	request()
	enabled = true
	wantFree = true
	request()
	// The old guarded approval callback may still be pending after lease expiry.
	// Its API retains the safe callback order, while an untouched legacy API does not.
	enabled = false
	request()
	if calls != 3 {
		t.Fatal(calls)
	}
}
