//go:build darwin && usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestInvitationRejectsCredentialAndDestinationConfusion(t *testing.T) {
	valid := invitation{URLs: []string{endpoint}, Pin: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
	b, _ := json.Marshal(valid)
	if _, err := decodeInvitation(b); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*invitation){
		func(i *invitation) { i.URLs = []string{"https://192.168.1.1:47775"} },
		func(i *invitation) { i.URLs = []string{endpoint + "/"} },
		func(i *invitation) { i.URLs = append(i.URLs, endpoint) },
		func(i *invitation) { i.Token = strings.Repeat("g", 64) },
		func(i *invitation) { i.Token = strings.Repeat("b", 63) + "\n" },
		func(i *invitation) { i.Pin = strings.Repeat("A", 64) },
	} {
		inv := valid
		mutate(&inv)
		data, _ := json.Marshal(inv)
		if _, err := decodeInvitation(data); err == nil {
			t.Fatalf("accepted invalid invitation: %s", data)
		}
	}
	for _, data := range [][]byte{append(append([]byte{}, b...), []byte(" {}")...), []byte(strings.Repeat(" ", 4097)),
		[]byte(strings.TrimSuffix(string(b), "}") + `,"transport":"usb-recovery"}`)} {
		if _, err := decodeInvitation(data); err == nil {
			t.Fatal("accepted trailing, oversized or extra transport data")
		}
	}
}

func TestTLSIsPinnedAndRejectsDowngrade(t *testing.T) {
	certificate := &x509.Certificate{Raw: []byte("synthetic exact certificate")}
	h := sha256.Sum256(certificate.Raw)
	cfg := pinnedTLS(hex.EncodeToString(h[:]))
	if cfg.MinVersion != tls.VersionTLS13 || cfg.VerifyConnection == nil {
		t.Fatal("missing mandatory certificate pin")
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{certificate}}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatal(err)
	}
	state.Version = tls.VersionTLS12
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted TLS downgrade")
	}
	state.Version = tls.VersionTLS13
	state.PeerCertificates = nil
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted missing certificate")
	}
	state.PeerCertificates = []*x509.Certificate{{Raw: []byte("different")}}
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted changed certificate")
	}
}

func TestTransportCannotUseProxyRedirectOrDifferentDestination(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
	tr := usbTransport("10.6.9.1:47775", pinnedTLS(strings.Repeat("a", 64)))
	if tr.Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
	for _, target := range []string{"127.0.0.1:47775", "10.6.9.1:443", "example.invalid:47775", "[::1]:47775"} {
		if _, err := tr.DialContext(context.Background(), "tcp", target); err == nil {
			t.Fatal("accepted non-USB target")
		}
	}
	if _, err := tr.DialContext(context.Background(), "tcp6", "10.6.9.1:47775"); err == nil {
		t.Fatal("accepted IPv6")
	}
	c, done := newClient(invitation{Pin: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)})
	defer done()
	if c.http.CheckRedirect == nil || c.http.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect accepted")
	}
}

func TestRequestAuthenticationAndBoundedErrors(t *testing.T) {
	token := strings.Repeat("b", 64)
	calls := 0
	c := &client{token: token, http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != endpoint+"/v1/status" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("wrong authenticated target")
		}
		resp := reply("echoed secret: " + token)
		resp.StatusCode = 403
		return resp, nil
	})}}
	_, err := c.request(context.Background(), "GET", "/v1/status", nil, "", 0)
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("missing rejection or leaked credential")
	}
	for _, path := range []string{"//example.invalid", "/v1/status?token=x", "/v1/performance", "/v1/recovery-test"} {
		if _, err = c.request(context.Background(), "GET", path, nil, "", 0); err == nil {
			t.Fatal("unsupported path accepted")
		}
	}
	if calls != 1 {
		t.Fatal("unsupported request reached transport")
	}
	if _, err = readBounded(strings.NewReader(strings.Repeat("x", responseLimit+1)), responseLimit); err == nil {
		t.Fatal("unbounded response")
	}
}

func TestRejectionReportsOnlyFixedClassifications(t *testing.T) {
	secret := strings.Repeat("b", 64)
	for _, tc := range []struct{ body, want string }{
		{"staging failed: LOCAL_REMOTE_STAGED_BYTES_RECOVERY_REQUIRED\n", ": LOCAL_REMOTE_STAGED_BYTES_RECOVERY_REQUIRED"},
		{"staging failed: LOCAL_REMOTE_JOB_PENDING: " + secret, ": LOCAL_REMOTE_JOB_PENDING"},
		{"staging failed: remove private/" + secret + ": The directory is not empty.\n", ": The directory is not empty."},
		{"staging failed: upgrade mutex security rejected: " + secret, ": upgrade mutex unavailable"},
		{"echoed secret: " + secret, ""},
		{"LOCAL_REMOTE_JOB_PENDING_" + secret, ""},
		{"staging failed: " + secret, ""},
	} {
		if got := rejectionReason([]byte(tc.body)); got != tc.want || strings.Contains(got, secret) {
			t.Fatalf("unsafe or incorrect classification: %q", got)
		}
	}
}

func testPublisher(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := remoteupdate.LocalPublisherHex
	remoteupdate.LocalPublisherHex = hex.EncodeToString(public)
	t.Cleanup(func() { remoteupdate.LocalPublisherHex = old })
	return private
}

func signedFixture(t *testing.T) (string, string, remoteupdate.Manifest) {
	t.Helper()
	private := testPublisher(t)
	dir := t.TempDir()
	executable := filepath.Join(dir, "installer.exe")
	manifest := filepath.Join(dir, "manifest.json")
	body := bytes.Repeat([]byte("signed installer"), 128)
	h := sha256.Sum256(body)
	m := remoteupdate.Manifest{Product: remoteupdate.Product, Version: "1.2.4", Bytes: int64(len(body)),
		SHA256: hex.EncodeToString(h[:]), Expires: time.Now().Add(time.Hour).Unix()}
	m.Sign(private)
	data, _ := json.Marshal(m)
	if err := os.WriteFile(executable, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	return executable, manifest, m
}

func TestUploadValidatesBytesAndExactAcknowledgements(t *testing.T) {
	exe, manifest, m := signedFixture(t)
	id := strings.Repeat("a", 32)
	for _, stageOnly := range []bool{true, false} {
		paths := []string{}
		c := &client{token: strings.Repeat("b", 64), http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			paths = append(paths, r.URL.Path)
			if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
				t.Fatal("missing authenticated POST")
			}
			if r.URL.Path == "/v1/prepare" {
				if r.ContentLength != m.Bytes {
					t.Fatal("wrong declared length")
				}
				data, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Suhang-Release"))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := remoteupdate.Decode(data)
				if err != nil || decoded != m {
					t.Fatal("manifest changed")
				}
				if err := remoteupdate.VerifyBinary(r.Body, m); err != nil {
					t.Fatal(err)
				}
				return reply(fmt.Sprintf(`{"id":%q,"version":"1.2.4","status":"verified"}`, id)), nil
			}
			var apply map[string]string
			if json.NewDecoder(r.Body).Decode(&apply) != nil || len(apply) != 1 || apply["id"] != id {
				t.Fatal("wrong apply identity")
			}
			return reply(fmt.Sprintf(`{"id":%q,"status":"installation_pending"}`, id)), nil
		})}}
		var output bytes.Buffer
		if err := upload(context.Background(), c, manifest, exe, "1.2.3", stageOnly, &output); err != nil {
			t.Fatal(err)
		}
		want := 2
		if stageOnly {
			want = 1
		}
		if len(paths) != want {
			t.Fatalf("unexpected requests: %v", paths)
		}
		if !stageOnly && !strings.Contains(output.String(), "does not confirm installation") {
			t.Fatal("acknowledgement promoted to installation success")
		}
	}
}

func TestUploadRejectsUnsignedOldAndChangedBytesBeforeTransmission(t *testing.T) {
	exe, manifest, m := signedFixture(t)
	c := &client{http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid release transmitted")
		return nil, fmt.Errorf("blocked")
	})}}
	if upload(context.Background(), c, manifest, exe, m.Version, false, io.Discard) == nil {
		t.Fatal("accepted same version")
	}
	if err := os.WriteFile(exe, []byte("changed bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if upload(context.Background(), c, manifest, exe, "1.2.3", false, io.Discard) == nil {
		t.Fatal("accepted wrong hash")
	}
	m.Signature = "invalid"
	data, _ := json.Marshal(m)
	os.WriteFile(manifest, data, 0600)
	if upload(context.Background(), c, manifest, exe, "1.2.3", false, io.Discard) == nil {
		t.Fatal("accepted invalid signature")
	}
}

func TestInvalidStagingAckNeverApplies(t *testing.T) {
	exe, manifest, _ := signedFixture(t)
	for _, ack := range []string{`{"id":"arbitrary"}`, `{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"1.2.3","status":"verified"}`} {
		calls := 0
		c := &client{http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return reply(ack), nil })}}
		if upload(context.Background(), c, manifest, exe, "1.2.3", false, io.Discard) == nil || calls != 1 {
			t.Fatal("invalid acknowledgement applied")
		}
	}
}

func TestInitKeyIsPrivateExclusiveAndOutputsOnlyPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	var output bytes.Buffer
	if err := run([]string{"--init-key", path}, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(private) != 64 {
		t.Fatal("invalid private key")
	}
	if output.String() != hex.EncodeToString(private[32:])+"\n" || strings.Contains(output.String(), hex.EncodeToString(private)) {
		t.Fatal("private key leaked or wrong public output")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions")
	}
	if run([]string{"--init-key", path}, io.Discard) == nil {
		t.Fatal("overwrote existing key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("changed existing key")
	}
}

func TestSigningDoesNotTransmitAndDoesNotOverwrite(t *testing.T) {
	private := testPublisher(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	exe := filepath.Join(dir, "exe")
	manifest := filepath.Join(dir, "manifest")
	os.WriteFile(key, []byte(hex.EncodeToString(private)), 0600)
	os.WriteFile(exe, bytes.Repeat([]byte("x"), 1024), 0600)
	args := []string{"--sign-key", key, "--version", "1.2.4", "--exe", exe, "--manifest", manifest}
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("signing printed private content")
	}
	b, _ := os.ReadFile(manifest)
	m, err := remoteupdate.Decode(b)
	if err != nil || m.Verify(remoteupdate.PublisherKey(), "1.2.3", time.Now()) != nil {
		t.Fatal("invalid signed manifest")
	}
	if run(args, io.Discard) == nil {
		t.Fatal("overwrote existing manifest")
	}
}

func TestCancelUsesExactCurrentIdleJobAndChecksAcknowledgement(t *testing.T) {
	id := strings.Repeat("a", 32)
	staged := []byte(fmt.Sprintf(`{"update":{"id":%q,"status":"staged"}}`, id))
	for index, ack := range []string{
		fmt.Sprintf(`{"id":%q,"status":"cancelled"}`, id),
		`{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"cancelled"}`,
		fmt.Sprintf(`{"id":%q,"status":"installation_pending"}`, id),
	} {
		calls := 0
		c := &client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			var body map[string]string
			if r.URL.Path != "/v1/cancel" || r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["id"] != id {
				t.Fatal("wrong cancel identity")
			}
			return reply(ack), nil
		})}}
		err := cancelStaged(context.Background(), c, staged, io.Discard)
		if (err == nil) != (index == 0) || calls != 1 {
			t.Fatal("wrong cancellation outcome")
		}
		for _, state := range []string{"installing", "dispatching", "awaiting_local_approval", "complete", "persistence_recovery_required"} {
			data := []byte(fmt.Sprintf(`{"update":{"id":%q,"status":%q}}`, id, state))
			if cancelStaged(context.Background(), c, data, io.Discard) == nil {
				t.Fatal("accepted non-idle or unproven retry")
			}
		}
		if calls != 1 {
			t.Fatal("unsafe cancellation transmitted")
		}
	}
}
