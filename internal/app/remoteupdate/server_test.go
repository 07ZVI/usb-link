package remoteupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func signed(t *testing.T) (ed25519.PublicKey, Manifest, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := bytes.Repeat([]byte{42}, 4096)
	h := sha256.Sum256(b)
	m := Manifest{Product: Product, Version: "0.7.8", Bytes: int64(len(b)), SHA256: hex.EncodeToString(h[:]), Expires: time.Now().Add(time.Hour).Unix()}
	m.Sign(key)
	return pub, m, b
}
func TestManifestRejectsTamperDowngradeExpiry(t *testing.T) {
	key, m, _ := signed(t)
	if e := m.Verify(key, "0.7.7", time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Manifest){func(x *Manifest) { x.Version = "0.7.6" }, func(x *Manifest) { x.Bytes++ }, func(x *Manifest) { x.Product = "other" }, func(x *Manifest) { x.SHA256 = strings.Repeat("0", 64) }, func(x *Manifest) { x.Expires++ }, func(x *Manifest) { x.Signature = "" }} {
		bad := m
		change(&bad)
		if bad.Verify(key, "0.7.7", time.Now()) == nil {
			t.Fatal("tampered manifest accepted")
		}
	}
	if m.Verify(key, "0.7.8", time.Now()) == nil || m.Verify(key, "0.7.7", time.Now().Add(2*time.Hour)) == nil {
		t.Fatal("replay or expired release accepted")
	}
}
func TestBinaryRejectsTruncationExtraAndCorruption(t *testing.T) {
	_, m, b := signed(t)
	if VerifyBinary(bytes.NewReader(b), m) != nil {
		t.Fatal("valid bytes rejected")
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), bytes.Repeat([]byte{1}, len(b))} {
		if VerifyBinary(bytes.NewReader(bad), m) == nil {
			t.Fatal("invalid binary accepted")
		}
	}
}
func TestTLSUploadMustValidateBeforeHandoffAndCannotReplay(t *testing.T) {
	key, m, b := signed(t)
	var stageCalls, applyCalls atomic.Int32
	s := &Server{Version: "0.7.7", Token: strings.Repeat("a", 64), Key: key, Stage: func(g Manifest, r io.Reader) (string, error) {
		stageCalls.Add(1)
		if e := VerifyBinary(r, g); e != nil {
			return "", e
		}
		return "verified-job", nil
	}, Apply: func(id string) error { applyCalls.Add(1); return nil }, Status: func() any { return map[string]string{"status": "idle"} }}
	h := httptest.NewTLSServer(s)
	defer h.Close()
	client := h.Client()
	req := func(method, path, token, origin, header string, body []byte) int {
		t.Helper()
		q, _ := http.NewRequest(method, h.URL+path, bytes.NewReader(body))
		q.Header.Set("Authorization", "Bearer "+token)
		q.Header.Set("Origin", origin)
		q.Header.Set("X-Suhang-Release", header)
		v, e := client.Do(q)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, v.Body)
		v.Body.Close()
		return v.StatusCode
	}
	for _, path := range []string{"/v1/auto-upgrade", "/v1/config", "/v1/consent"} {
		if req("POST", path, s.Token, "", "", []byte(`{"auto_upgrade":true}`)) != 404 {
			t.Fatal("remote consent endpoint exposed")
		}
	}
	data, _ := json.Marshal(m)
	header := base64.StdEncoding.EncodeToString(data)
	if req("GET", "/v1/status", "bad", "", "", nil) != 403 || req("GET", "/v1/status", s.Token, "https://foreign.invalid", "", nil) != 403 {
		t.Fatal("authentication bypass")
	}
	if req("POST", "/v1/apply", s.Token, "", "", []byte(`{"id":"verified-job"}`)) != 409 || applyCalls.Load() != 0 {
		t.Fatal("apply before staging")
	}
	if req("POST", "/v1/prepare", s.Token, "", header, bytes.Repeat([]byte{3}, len(b))) != 422 || applyCalls.Load() != 0 {
		t.Fatal("corrupt body handoff")
	}
	if req("POST", "/v1/prepare", s.Token, "", header, b) != 200 || applyCalls.Load() != 0 {
		t.Fatal("staging should not apply")
	}
	if req("POST", "/v1/apply", s.Token, "", "", []byte(`{"id":"wrong"}`)) != 409 {
		t.Fatal("job mismatch")
	}
	if req("POST", "/v1/apply", s.Token, "", "", []byte(`{"id":"verified-job"}`)) != 202 || applyCalls.Load() != 1 {
		t.Fatal("valid apply should request local approval")
	}
	if req("POST", "/v1/apply", s.Token, "", "", []byte(`{"id":"verified-job"}`)) != 409 || applyCalls.Load() != 1 {
		t.Fatal("duplicate handoff")
	}
	s.Reset()
	if req("POST", "/v1/prepare", s.Token, "", header, b) != 200 {
		t.Fatal("declined request could not be replaced")
	}
	if stageCalls.Load() != 3 {
		t.Fatal(stageCalls.Load())
	}
	q := httptest.NewRequest("GET", "http://10.6.9.1/v1/status", nil)
	q.Header.Set("Authorization", "Bearer "+s.Token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, q)
	if w.Code != 403 {
		t.Fatal("plaintext accepted")
	}
	q.TLS = &tls.ConnectionState{}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, q)
	if w.Code != 200 {
		t.Fatal("TLS status failed")
	}
}
