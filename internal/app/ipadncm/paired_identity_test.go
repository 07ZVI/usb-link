package ipadncm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"howett.net/plist"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func fixtureCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})
}
func answerFixture(c net.Conn, answer map[string]any) error {
	h := make([]byte, 4)
	if _, e := io.ReadFull(c, h); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(h)
	if n > 512*1024 {
		return io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	reply, e := plist.Marshal(answer, plist.XMLFormat)
	if e != nil {
		return e
	}
	binary.BigEndian.PutUint32(h, uint32(len(reply)))
	if e = writeAll(c, h); e != nil {
		return e
	}
	return writeAll(c, reply)
}
func TestPairAuthenticationRequiresTLSDeviceKeyAndAuthenticatedIdentity(t *testing.T) {
	hostCert, hostKey := fixtureCertificate(t)
	deviceCert, deviceKey := fixtureCertificate(t)
	otherCert, otherKey := fixtureCertificate(t)
	pair, _ := plist.Marshal(map[string]any{"HostID": "host", "SystemBUID": "buid", "RootCertificate": hostCert, "RootPrivateKey": hostKey, "DeviceCertificate": deviceCert}, plist.XMLFormat)
	for _, tt := range []struct {
		name, uid string
		cert, key []byte
		want      bool
	}{{"correct", "0000810300123456789abcde", deviceCert, deviceKey, true}, {"spoofed serial correct-looking plaintext", "0000810300123456789abcde", otherCert, otherKey, false}, {"other authenticated serial", "0000810300123456789fffff", deviceCert, deviceKey, false}} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				server.SetDeadline(time.Now().Add(4 * time.Second))
				if answerFixture(server, map[string]any{"EnableSessionSSL": true, "SessionID": "session"}) != nil {
					return
				}
				cert, e := tls.X509KeyPair(tt.cert, tt.key)
				if e != nil {
					return
				}
				secured := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert})
				if secured.Handshake() != nil {
					return
				}
				if answerFixture(secured, map[string]any{"Value": tt.uid}) != nil {
					return
				}
				if answerFixture(secured, map[string]any{"Value": "iPad13,16"}) != nil {
					return
				}
				answerFixture(secured, map[string]any{"Request": "StopSession"})
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			p := authenticatePair(ctx, "00008103-00123456789abcde", pair, func(context.Context) (net.Conn, error) { return client, nil })
			client.Close()
			<-done
			if p.Authenticated != tt.want {
				t.Fatal(p)
			}
			if !p.Authenticated && (p.identity != "" || p.key != "") {
				t.Fatal("unverified identity persisted")
			}
		})
	}
}
