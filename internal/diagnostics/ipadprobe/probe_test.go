package ipadprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestPlistWireBoundsAndFormats(t *testing.T) {
	for _, mux := range []bool{false, true} {
		var b bytes.Buffer
		original := map[string]any{"Number": uint64(17), "Data": []byte{1, 2, 3}, "Array": []any{"USB", uint64(3)}}
		if err := sendPlist(&b, original, mux); err != nil {
			t.Fatal(err)
		}
		d, err := readPlist(&b, mux)
		if err != nil {
			t.Fatal(err)
		}
		if number(d["Number"]) != 17 || !bytes.Equal(d["Data"].([]byte), []byte{1, 2, 3}) {
			t.Fatal("plist types lost")
		}
	}
	for _, n := range []uint32{0, maxFrame + 1, 0xffffffff} {
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, n)
		if _, err := readPlist(bytes.NewReader(h), false); err == nil {
			t.Fatal("accepted invalid allocation size")
		}
	}
	b, _ := plist.Marshal(map[string]any{"HostPrivateKey": []byte("secret")}, plist.BinaryFormat)
	var d map[string]any
	if _, err := plist.Unmarshal(b, &d); err != nil || !bytes.Equal(d["HostPrivateKey"].([]byte), []byte("secret")) {
		t.Fatal("binary pair record unsupported")
	}
}
func TestMalformedIPv6AndTruncation(t *testing.T) {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], 65535)
	if _, err := readIPv6(bytes.NewReader(h), 16000); err == nil {
		t.Fatal("accepted oversized packet")
	}
	binary.BigEndian.PutUint16(h[4:], 8)
	if _, err := readIPv6(bytes.NewReader(h), 16000); err != io.EOF {
		t.Fatalf("truncation: %v", err)
	}
}
func TestRepliesMustMatchAddressesNonceAndChecksum(t *testing.T) {
	local, remote := net.ParseIP("fd00::2"), net.ParseIP("fd00::1")
	echo := []byte{128, 0, 0, 0, 0x12, 0x34, 0, 1, 10, 20, 30, 40}
	reply := append([]byte(nil), echo...)
	reply[0] = 129
	good := ipv6Packet(remote, local, 58, reply)
	if !validEchoReply(good, local, remote, echo) {
		t.Fatal("valid echo rejected")
	}
	for _, index := range []int{8, 24, 42, 44, 48} {
		bad := append([]byte(nil), good...)
		bad[index] ^= 1
		if validEchoReply(bad, local, remote, echo) {
			t.Fatal("accepted corrupt, foreign or wrong nonce reply")
		}
	}
	syn := make([]byte, 20)
	binary.BigEndian.PutUint16(syn, 45001)
	binary.BigEndian.PutUint16(syn[2:], 58783)
	binary.BigEndian.PutUint32(syn[4:], 345)
	response := make([]byte, 20)
	copy(response[:2], syn[2:4])
	copy(response[2:4], syn[:2])
	binary.BigEndian.PutUint32(response[8:], 346)
	response[12] = 0x50
	response[13] = 0x12
	if !validSYNACK(ipv6Packet(remote, local, 6, response), local, remote, syn) {
		t.Fatal("valid SYNACK rejected")
	}
	binary.BigEndian.PutUint32(response[8:], 347)
	if validSYNACK(ipv6Packet(remote, local, 6, response), local, remote, syn) {
		t.Fatal("wrong acknowledgement accepted")
	}
	response[13] = 0x14
	if validSYNACK(ipv6Packet(remote, local, 6, response), local, remote, syn) {
		t.Fatal("RST counted as success")
	}
}
func TestResultHasNoCredentialOrPersonalDataFields(t *testing.T) {
	b, err := json.Marshal(Result{Status: "RAW_IPV6_ROUNDTRIP_CONFIRMED"})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"HostPrivateKey", "HostID", "SystemBUID", "DeviceCertificate", "SerialNumber", "PairRecordData", "EscrowBag"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("sensitive result field", secret)
		}
	}
	var fields map[string]any
	json.Unmarshal(b, &fields)
	if fields["moonlight_verified"] != false || fields["bandwidth_measured"] != false {
		t.Fatal("raw probe promoted to streaming or speed acceptance")
	}
}

func TestTLSRequiresExactPairedDeviceCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	makeCert := func(serial int64) []byte {
		t.Helper()
		x := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, er := x509.CreateCertificate(rand.Reader, x, x, &key.PublicKey, key)
		if er != nil {
			t.Fatal(er)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	expected, different := makeCert(1), makeCert(2)
	for _, tc := range []struct {
		name string
		cert []byte
		ok   bool
	}{{"paired", expected, true}, {"same_key_different_certificate", different, false}} {
		t.Run(tc.name, func(t *testing.T) {
			serverCert, er := tls.X509KeyPair(tc.cert, keyPEM)
			if er != nil {
				t.Fatal(er)
			}
			listener, er := net.Listen("tcp", "127.0.0.1:0")
			if er != nil {
				t.Fatal(er)
			}
			defer listener.Close()
			client, er := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if er != nil {
				t.Fatal(er)
			}
			defer client.Close()
			server, er := listener.Accept()
			if er != nil {
				t.Fatal(er)
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				s := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert})
				done <- s.HandshakeContext(ctx)
			}()
			_, er = pinnedTLS(ctx, client, map[string]any{"HostCertificate": expected, "HostPrivateKey": keyPEM, "DeviceCertificate": expected})
			if (er == nil) != tc.ok {
				t.Fatalf("pin result: %v", er)
			}
			client.Close()
			server.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("TLS peer did not stop")
			}
		})
	}
}
