package ipadncm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"howett.net/plist"
	"io"
	"net"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"time"
)

type PairedIdentity struct {
	Authenticated          bool   `json:"paired_tls_device_authenticated"`
	Error                  string `json:"paired_authentication_error,omitempty"`
	identity, key, product string
}

func (p PairedIdentity) Grant() ipadsession.DeviceGrant {
	return ipadsession.DeviceGrant{Identity: p.identity, Key: p.key, Product: p.product}
}
func exchangeLockdown(c net.Conn, m map[string]any) (map[string]any, error) {
	b, e := plist.Marshal(m, plist.XMLFormat)
	if e != nil {
		return nil, e
	}
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(len(b)))
	if writeAll(c, h) != nil || writeAll(c, b) != nil {
		return nil, fmt.Errorf("lockdown write")
	}
	if _, e = io.ReadFull(c, h); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h)
	if n == 0 || n > 512*1024 {
		return nil, fmt.Errorf("lockdown size")
	}
	b = make([]byte, n)
	if _, e = io.ReadFull(c, b); e != nil {
		return nil, e
	}
	var out map[string]any
	_, e = plist.Unmarshal(b, &out)
	if e != nil || out["Error"] != nil {
		return nil, fmt.Errorf("lockdown rejected")
	}
	return out, nil
}
func certificatePin(raw []byte) (string, error) {
	b, _ := pem.Decode(raw)
	if b == nil {
		return "", fmt.Errorf("certificate PEM required")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:]), nil
}
func canonicalSerial(s string) string { return strings.ToLower(strings.ReplaceAll(s, "-", "")) }

// Authentication uses only the USB transport, existing Apple credentials and
// a TLS key challenge. It never pairs/unpairs, starts data services or saves keys.
func authenticatePair(ctx context.Context, serial string, pairData []byte, connect func(context.Context) (net.Conn, error)) (out PairedIdentity) {
	out.Error = "PAIRED_CERTIFICATE_NOT_VERIFIED"
	var record map[string]any
	if len(pairData) == 0 || len(pairData) > 512*1024 {
		return
	}
	if _, e := plist.Unmarshal(pairData, &record); e != nil {
		return
	}
	hostID, _ := record["HostID"].(string)
	buid, _ := record["SystemBUID"].(string)
	cert, _ := record["RootCertificate"].([]byte)
	key, _ := record["RootPrivateKey"].([]byte)
	device, _ := record["DeviceCertificate"].([]byte)
	if hostID == "" || len(hostID) > 128 || buid == "" || len(buid) > 128 {
		return
	}
	host, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return
	}
	pin, e := certificatePin(device)
	if e != nil {
		return
	}
	c, e := connect(ctx)
	if e != nil {
		out.Error = "PAIRED_USB_TRANSPORT_UNAVAILABLE"
		return
	}
	defer c.Close()
	c.SetDeadline(queryDeadline(ctx, 5*time.Second))
	response, e := exchangeLockdown(c, map[string]any{"Request": "StartSession", "Label": "Suhang-USB", "HostID": hostID, "SystemBUID": buid})
	sid, _ := response["SessionID"].(string)
	if e != nil || sid == "" || response["EnableSessionSSL"] != true {
		out.Error = "PAIRED_TLS_SESSION_REQUIRED"
		return
	}
	secured := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{host}, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return fmt.Errorf("no device certificate")
		}
		h := sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(h[:]) != pin {
			return fmt.Errorf("paired device key mismatch")
		}
		return nil
	}})
	if e = secured.HandshakeContext(ctx); e != nil {
		out.Error = "PAIRED_TLS_KEY_PROOF_FAILED"
		return
	}
	defer func() {
		secured.SetDeadline(time.Now().Add(time.Second))
		exchangeLockdown(secured, map[string]any{"Request": "StopSession", "Label": "Suhang-USB", "SessionID": sid})
		secured.Close()
	}()
	uid, e := exchangeLockdown(secured, map[string]any{"Request": "GetValue", "Key": "UniqueDeviceID", "Label": "Suhang-USB"})
	v, _ := uid["Value"].(string)
	if e != nil || canonicalSerial(v) != canonicalSerial(serial) {
		out.Error = "PAIRED_AUTHENTICATED_USB_IDENTITY_MISMATCH"
		return
	}
	product, e := exchangeLockdown(secured, map[string]any{"Request": "GetValue", "Key": "ProductType", "Label": "Suhang-USB"})
	model, _ := product["Value"].(string)
	if e != nil || model != "iPad13,16" {
		out.Error = "PAIRED_AUTHENTICATED_PRODUCT_MISMATCH"
		return
	}
	out.Authenticated = true
	out.Error = ""
	out.identity = ipadsession.DeviceIdentity(canonicalSerial(serial))
	out.key = pin
	out.product = model
	return
}
