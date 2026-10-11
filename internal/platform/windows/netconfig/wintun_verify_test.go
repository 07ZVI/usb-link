package netconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestWintunNativePathBoundary(t *testing.T) {
	for _, path := range []string{`C:\USB Link\runtime\wintun.dll`, `c:\wintun.dll`, `D:\工具\wintun.dll`} {
		if _, err := wintunLocalPathParts(path); err != nil {
			t.Fatalf("valid local path %q: %v", path, err)
		}
	}
	for _, path := range []string{`wintun.dll`, `C:wintun.dll`, `\\server\share\wintun.dll`, `\\?\C:\wintun.dll`, `C:\x\wintun.dll:stream`, `C:\x\..\wintun.dll`, `C:\.\wintun.dll`, `C:\x.\wintun.dll`, `C:\x \wintun.dll`, `C:\CON\wintun.dll`, `C:\COM1\wintun.dll`, `C:\x\\wintun.dll`, `C:\x\other.dll`, `C:/x/wintun.dll`, "C:\\x\x00\\wintun.dll", `C:\*\wintun.dll`} {
		if _, err := wintunLocalPathParts(path); err == nil {
			t.Errorf("accepted ambiguous/nonlocal path %q", path)
		}
	}
}

func wintunTestCertificate(t *testing.T, cn string, extra []pkix.AttributeTypeAndValue) []byte {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, ExtraNames: extra}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestWintunNativePublisherStrictPrimaryCN(t *testing.T) {
	for _, cn := range []string{"WireGuard LLC", "wireguard llc"} {
		if err := wintunPublisherCertificate(wintunTestCertificate(t, cn, nil)); err != nil {
			t.Fatal(err)
		}
	}
	for _, cn := range []string{"", "Microsoft Corporation", "WireGuard LLC attacker", " WireGuard LLC", "WireGuard LLC ", "CN=WireGuard LLC"} {
		if err := wintunPublisherCertificate(wintunTestCertificate(t, cn, nil)); err == nil {
			t.Errorf("accepted publisher %q", cn)
		}
	}
	duplicate := []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "WireGuard LLC"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "WireGuard LLC"}}
	if err := wintunPublisherCertificate(wintunTestCertificate(t, "", duplicate)); err == nil {
		t.Fatal("accepted duplicate CN")
	}
	for _, der := range [][]byte{nil, []byte("WireGuard LLC"), make([]byte, 128*1024+1)} {
		if err := wintunPublisherCertificate(der); err == nil {
			t.Fatal("accepted invalid certificate")
		}
	}
	// This helper accepts even an expired/self-signed test certificate only as
	// a publisher parser. Windows trust must succeed independently in production.
}
