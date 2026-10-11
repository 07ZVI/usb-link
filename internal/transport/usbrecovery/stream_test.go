package usbrecovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pair(t *testing.T, loss bool) (*Conn, *Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var id [16]byte
	id[0] = 17
	ab, ba := make(chan []byte, 128), make(chan []byte, 128)
	send := func(ch chan []byte) func([]byte) error {
		return func(p []byte) error {
			select {
			case ch <- append([]byte(nil), p...):
				return nil
			case <-ctx.Done():
				return io.ErrClosedPipe
			}
		}
	}
	a, b := NewConn(ctx, id, send(ab)), NewConn(ctx, id, send(ba))
	var workers sync.WaitGroup
	deliver := func(ch chan []byte, to *Conn) {
		defer workers.Done()
		count := 0
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-ch:
				count++
				if loss && count%17 == 0 {
					continue
				}
				to.Ingest(p)
				if loss && count%11 == 0 {
					to.Ingest(p)
				}
			}
		}
	}
	workers.Add(2)
	go deliver(ab, b)
	go deliver(ba, a)
	t.Cleanup(func() { cancel(); workers.Wait() })
	return a, b
}
func TestReliableWindowLossDuplicateAndDuplex(t *testing.T) {
	a, b := pair(t, true)
	a.SetDeadline(time.Now().Add(12 * time.Second))
	b.SetDeadline(time.Now().Add(12 * time.Second))
	data := bytes.Repeat([]byte("abcdefgh"), 32768)
	other := bytes.Repeat([]byte("reverse"), 12345)
	writes := make(chan error, 2)
	go func() { _, e := a.Write(data); writes <- e }()
	go func() { _, e := b.Write(other); writes <- e }()
	reads := make(chan error, 2)
	go func() {
		buf := make([]byte, len(data))
		_, e := io.ReadFull(b, buf)
		if e == nil && !bytes.Equal(buf, data) {
			e = errors.New("forward corruption")
		}
		reads <- e
	}()
	go func() {
		buf := make([]byte, len(other))
		_, e := io.ReadFull(a, buf)
		if e == nil && !bytes.Equal(buf, other) {
			e = errors.New("reverse corruption")
		}
		reads <- e
	}()
	for i := 0; i < 2; i++ {
		if e := <-writes; e != nil {
			t.Fatal(e)
		}
		if e := <-reads; e != nil {
			t.Fatal(e)
		}
	}
}
func TestWrongSessionOrderingAndBackpressure(t *testing.T) {
	c := NewConn(context.Background(), [16]byte{1}, func([]byte) error { return nil })
	defer c.Close()
	forged := c.packet(1, 0, []byte("bad"))
	forged[6]++
	if c.Ingest(forged) {
		t.Fatal("foreign session accepted")
	}
	if c.Ingest(c.packet(2, 99, nil)) {
		t.Fatal("future ACK accepted")
	}
	c.Ingest(c.packet(1, 1, []byte("gap")))
	if len(c.input) != 0 {
		t.Fatal("out-of-order packet queued")
	}
	for i := 0; i < 64; i++ {
		c.Ingest(c.packet(1, uint64(i), []byte("x")))
	}
	if len(c.input) != 32 || c.rx != 32 {
		t.Fatalf("queue not bounded %d/%d", len(c.input), c.rx)
	}
}
func TestDeadlineChangesAndCloseInterrupt(t *testing.T) {
	for _, write := range []bool{false, true} {
		c := NewConn(context.Background(), [16]byte{1}, func([]byte) error { return nil })
		done := make(chan error, 1)
		go func() {
			if write {
				_, e := c.Write([]byte("no ack"))
				done <- e
			} else {
				_, e := c.Read(make([]byte, 1))
				done <- e
			}
		}()
		time.Sleep(10 * time.Millisecond)
		c.SetDeadline(time.Now().Add(20 * time.Millisecond))
		select {
		case e := <-done:
			if !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("deadline did not wake operation")
		}
		c.Close()
	}
	a, b := pair(t, false)
	done := make(chan error, 1)
	go func() { _, e := b.Read(make([]byte, 1)); done <- e }()
	a.Close()
	select {
	case e := <-done:
		if e != io.EOF {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not reach peer")
	}
}
func TestTLSMaintenanceStatusSignedUploadAndApply(t *testing.T) {
	a, b := pair(t, true)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256(der)
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	blob := bytes.Repeat([]byte("signed candidate payload"), 65536)
	sum := sha256.Sum256(blob)
	var applied atomic.Bool
	api := &remoteupdate.Server{Version: "0.8.33", Token: strings.Repeat("a", 64), Key: pub, Status: func() any { return "idle" }, Diagnostics: func() any { return map[string]string{"error": "RECOVERY_PENDING"} }, Stage: func(m remoteupdate.Manifest, r io.Reader) (string, error) {
		data, e := io.ReadAll(r)
		if e != nil {
			return "", e
		}
		if !bytes.Equal(data, blob) {
			return "", errors.New("corrupt staged body")
		}
		if e = remoteupdate.VerifyBinary(bytes.NewReader(data), m); e != nil {
			return "", e
		}
		return "test-job", nil
	}, Apply: func(id string) error {
		if id != "test-job" {
			return errors.New("bad job")
		}
		applied.Store(true)
		return nil
	}}
	listener := NewListener(b)
	server := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}))
	}()
	t.Cleanup(func() { server.Close(); listener.Close(); <-done })
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return a, nil }, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		got := sha256.Sum256(state.PeerCertificates[0].Raw)
		if got != pin {
			return errors.New("pin mismatch")
		}
		return nil
	}}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	request := func(path, token string, body io.Reader, m *remoteupdate.Manifest) int {
		t.Helper()
		method := "POST"
		if path == "/v1/status" {
			method = "GET"
		}
		q, _ := http.NewRequest(method, "https://10.6.9.1:47775"+path, body)
		q.Header.Set("Authorization", "Bearer "+token)
		if m != nil {
			h, _ := json.Marshal(m)
			q.Header.Set("X-Suhang-Release", base64.StdEncoding.EncodeToString(h))
			q.ContentLength = m.Bytes
		}
		r, e := client.Do(q)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		data, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		if r.StatusCode >= 500 {
			t.Fatalf("server %d: %s", r.StatusCode, data)
		}
		return r.StatusCode
	}
	token := strings.Repeat("a", 64)
	if got := request("/v1/status", strings.Repeat("b", 64), nil, nil); got != 403 {
		t.Fatal(got)
	}
	if got := request("/v1/status", token, nil, nil); got != 200 {
		t.Fatal(got)
	}
	manifest := remoteupdate.Manifest{Product: remoteupdate.Product, Version: "0.8.34", Bytes: int64(len(blob)), SHA256: hex.EncodeToString(sum[:]), Expires: time.Now().Add(time.Hour).Unix()}
	manifest.Sign(private)
	tampered := manifest
	tampered.Version = "0.8.35"
	tampered.Bytes = 1
	if got := request("/v1/prepare", token, strings.NewReader("x"), &tampered); got != 400 {
		t.Fatal(got)
	}
	if got := request("/v1/prepare", token, bytes.NewReader(blob), &manifest); got != 200 {
		t.Fatal(got)
	}
	if got := request("/v1/apply", token, strings.NewReader(`{"id":"foreign-job"}`), nil); got != 409 {
		t.Fatal(got)
	}
	if got := request("/v1/apply", token, strings.NewReader(`{"id":"test-job"}`), nil); got != 202 {
		t.Fatal(got)
	}
	// The HTTP response is only written after Apply; its receipt synchronizes the flag.
	if !applied.Load() {
		t.Fatal("apply callback absent")
	}
}
