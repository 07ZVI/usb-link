package remoteupdate

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPersistenceFailureLeaseExpiryExactCancellationRetryAndNewStage(t *testing.T) {
	for _, awaitingWriteFails := range []bool{false, true} {
		name := "declined-write"
		if awaitingWriteFails {
			name = "awaiting-write"
		}
		t.Run(name, func(t *testing.T) { persistenceFailureSequence(t, awaitingWriteFails) })
	}
}
func persistenceFailureSequence(t *testing.T, awaitingWriteFails bool) {
	key, manifest, binary := signed(t)
	headerJSON, _ := json.Marshal(manifest)
	enabled, reserved, failWrite := true, false, awaitingWriteFails
	durable := JobIdentity{Guarded: true, PID: 90, Creation: 123, Executable: "owned.exe"}
	var released, applyCalls, ordinaryPerf, stageCalls int
	var s *Server
	s = &Server{Version: "0.7.7", Token: strings.Repeat("a", 64), Key: key, Resilient: func() bool { return enabled }, Status: func() any { return durable }, Stage: func(m Manifest, r io.Reader) (string, error) {
		if reserved {
			return "", errors.New("existing guarded owner remains reserved")
		}
		if err := VerifyBinary(r, m); err != nil {
			return "", err
		}
		stageCalls++
		if stageCalls == 1 {
			durable.ID = strings.Repeat("b", 32)
		} else {
			durable.ID = strings.Repeat("c", 32)
		}
		durable.Status = "staged"
		reserved = true
		return durable.ID, nil
	}, Apply: func(id string) error {
		applyCalls++
		if failWrite {
			return RetainJobError(errors.New("disk full writing awaiting approval"))
		}
		durable.Status = "awaiting_local_approval"
		// The refusal/expiry terminal write fails while the exact parent stays alive.
		failWrite = true
		return RetainJobError(errors.New("disk full writing declined"))
	}, Cancel: func(id string) error {
		owner := durable
		owner.ID = id
		if !IdleTerminationRetryAllowed(durable, owner, []string{"staged", "awaiting_local_approval"}, false, false) {
			return errors.New("owner changed")
		}
		if failWrite {
			return RetainJobError(errors.New("disk full writing cancelled"))
		}
		durable.Status = "cancelled"
		reserved = false
		released++
		return nil
	}, Performance: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ordinaryPerf++; w.WriteHeader(200) }), PersistenceRecovery: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, err := DecodeGuardControl(http.MaxBytesReader(w, r.Body, 512), r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if q.Kind == "UPGRADEGUARDON" {
			enabled = true
		}
		w.WriteHeader(200)
	})}
	call := func(path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+s.Token)
		if path == "/v1/prepare" {
			req = httptest.NewRequest("POST", path, bytes.NewReader(binary))
			req.TLS = &tls.ConnectionState{}
			req.Header.Set("Authorization", "Bearer "+s.Token)
			req.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(headerJSON))
		}
		out := httptest.NewRecorder()
		s.ServeHTTP(out, req)
		return out.Code
	}
	if got := call("/v1/prepare", ""); got != 200 {
		t.Fatal(got)
	}
	id := durable.ID
	if got := call("/v1/apply", `{"id":"`+id+`"}`); got != 500 {
		t.Fatal(got)
	}
	wantedStatus := "awaiting_local_approval"
	if awaitingWriteFails {
		wantedStatus = "staged"
	}
	if s.job != id || !s.retrying || !reserved || released != 0 || applyCalls != 1 || durable.Status != wantedStatus {
		t.Fatal("write failure lost original task or changed process state")
	}
	// Expired lease neither erases the job nor grants worker execution.
	enabled = false
	if got := call("/v1/prepare", ""); got != 409 {
		t.Fatal("parallel stage accepted", got)
	}
	if got := call("/v1/apply", `{"id":"`+id+`"}`); got != 409 {
		t.Fatal("expired persistence recovery started worker", got)
	}
	if got := call("/v1/cancel", `{"id":"`+strings.Repeat("c", 32)+`"}`); got != 409 {
		t.Fatal("foreign cancellation accepted", got)
	}
	if got := call("/v1/cancel", `{"id":"`+id+`"}`); got != 409 || s.job != id || !reserved {
		t.Fatal("failed retry released task", got)
	}
	nonce := strings.Repeat("d", 32)
	if got := call("/v1/performance", `{"kind":"OTHER","seconds":0,"nonce":"`+nonce+`"}`); got != 400 || ordinaryPerf != 0 {
		t.Fatal("arbitrary performance command entered", got)
	}
	if got := call("/v1/performance", `{"kind":"UPGRADEGUARDON","seconds":900,"nonce":"`+nonce+`"}`); got != 200 || !enabled {
		t.Fatal("exact lease renewal unavailable", got)
	}
	failWrite = false
	if got := call("/v1/cancel", `{"id":"`+id+`"}`); got != 200 || reserved || s.job != "" || released != 1 || durable.Status != "cancelled" {
		t.Fatal("same-owner cancellation retry did not finish", got)
	}
	if got := call("/v1/prepare", ""); got != 200 {
		t.Fatal("new stage stayed permanently blocked", got)
	}
	if durable.ID == id || s.HoldOwned(id) || s.ResetOwned(id) || call("/v1/cancel", `{"id":"`+id+`"}`) != 409 || s.job != durable.ID || !reserved {
		t.Fatal("old recovery callback or ID changed new task")
	}
	if applyCalls != 1 {
		t.Fatal("idle recovery re-entered worker handoff")
	}
}

func TestInitialCommitErrorRetainsExactStageAndDoesNotAcknowledgeVerified(t *testing.T) {
	key, manifest, binary := signed(t)
	header, _ := json.Marshal(manifest)
	id := strings.Repeat("b", 32)
	s := &Server{Version: "0.7.7", Token: strings.Repeat("a", 64), Key: key, Resilient: func() bool { return true }, Stage: func(m Manifest, r io.Reader) (string, error) {
		if err := VerifyBinary(r, m); err != nil {
			return "", err
		}
		return id, RetainJobError(errors.New("post-commit write result unconfirmed"))
	}}
	req := httptest.NewRequest("POST", "/v1/prepare", bytes.NewReader(binary))
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(header))
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	if out.Code != 422 || s.job != id || !s.retrying || !strings.Contains(out.Body.String(), "persistence_recovery_required") {
		t.Fatalf("commit ambiguity discarded slot: %d %s", out.Code, out.Body.String())
	}
}

func TestStorageRetryCannotInferUnlaunchedFromMissingWorkerReceipt(t *testing.T) {
	owner := JobIdentity{ID: strings.Repeat("a", 32), Status: "staged", Guarded: true, PID: 9, Creation: 44, Executable: "owned.exe"}
	current := owner
	current.Status = "handoff"
	if !IdleTerminationRetryAllowed(current, owner, []string{"handoff"}, false, false) {
		t.Fatal("pre-CreateProcess handoff save could not be repaired")
	}
	// No worker PID is an input: positive live launch knowledge decides, not
	// the absence of a receipt after CreateProcess succeeded/save failed.
	for _, state := range []struct{ attempted, committed bool }{{true, false}, {false, true}, {true, true}} {
		if IdleTerminationRetryAllowed(current, owner, []string{"handoff"}, state.attempted, state.committed) {
			t.Fatal("unknown/started process downgraded to idle")
		}
	}
	changed := current
	changed.Creation++
	if IdleTerminationRetryAllowed(changed, owner, []string{"handoff"}, false, false) {
		t.Fatal("PID reuse accepted")
	}
}

func TestFixedPersistenceRecoveryControlsRejectExtraAuthority(t *testing.T) {
	nonce := strings.Repeat("f", 32)
	for _, body := range []string{`{"kind":"UPGRADEGUARDON","seconds":900,"nonce":"` + nonce + `"}`, `{"kind":"UPGRADEGUARDSTATE","seconds":0,"nonce":"` + nonce + `"}`, `{"kind":"UPGRADEGUARDOFF","seconds":0,"nonce":"` + nonce + `"}`} {
		if _, err := DecodeGuardControl(strings.NewReader(body), ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`{"kind":"UPGRADEGUARDON","seconds":901,"nonce":"` + nonce + `"}`, `{"kind":"UPGRADEGUARDON","seconds":900,"nonce":"` + nonce + `","command":"anything"}`, `{"kind":"UPGRADEGUARDSTATE","seconds":0,"nonce":"` + strings.Repeat("F", 32) + `"}`, `{"kind":"UPGRADEGUARDSTATE","seconds":0,"nonce":"` + nonce + `"} {}`} {
		if _, err := DecodeGuardControl(strings.NewReader(body), ""); err == nil {
			t.Fatal("authority expansion accepted", body)
		}
	}
}

func TestRecreatedListenerRetainsIdleRetryOrExecutingBarrier(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, retry := range []bool{true, false} {
		s := &Server{Token: strings.Repeat("b", 64), Resilient: func() bool { return false }, Cancel: func(string) error { return nil }, Performance: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("normal performance bypassed retained owner") }), PersistenceRecovery: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })}
		if !s.ResumeOwned(id, retry) || s.ResumeOwned(strings.Repeat("c", 32), true) {
			t.Fatal("listener lost/replaced live owner")
		}
		req := httptest.NewRequest("POST", "/v1/performance", strings.NewReader(`{}`))
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+s.Token)
		out := httptest.NewRecorder()
		s.ServeHTTP(out, req)
		want := 409
		if retry {
			want = 200
		}
		if out.Code != want {
			t.Fatalf("retry=%t status=%d", retry, out.Code)
		}
		req = httptest.NewRequest("POST", "/v1/cancel", strings.NewReader(`{"id":"`+id+`"}`))
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Authorization", "Bearer "+s.Token)
		out = httptest.NewRecorder()
		s.ServeHTTP(out, req)
		if retry && out.Code != 200 || !retry && out.Code == 200 {
			t.Fatalf("active/unknown listener cancelled: %d", out.Code)
		}
	}
}
