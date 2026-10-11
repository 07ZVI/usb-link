// Package remoteupdate accepts only publisher-signed Suhang release binaries.
package remoteupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const Product = "suhang-usb-windows-amd64"
const MaxBinary = 256 * 1024 * 1024

type Manifest struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Expires   int64  `json:"expires_unix"`
	Signature string `json:"signature"`
}

func version(v string) ([3]uint64, error) {
	var n [3]uint64
	p := strings.Split(v, ".")
	if len(p) != 3 {
		return n, fmt.Errorf("invalid version")
	}
	for i, s := range p {
		v, e := strconv.ParseUint(s, 10, 32)
		if e != nil || strconv.FormatUint(v, 10) != s {
			return n, fmt.Errorf("invalid version")
		}
		n[i] = v
	}
	return n, nil
}
func Newer(a, b string) bool {
	x, e := version(a)
	y, f := version(b)
	if e != nil || f != nil {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}
func (m Manifest) message() []byte {
	return []byte(fmt.Sprintf("SUHANG-UPDATE/1\n%s\n%s\n%d\n%s\n%d\n", m.Product, m.Version, m.Bytes, m.SHA256, m.Expires))
}
func (m *Manifest) Sign(key ed25519.PrivateKey) {
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.message()))
}
func (m Manifest) Verify(key ed25519.PublicKey, current string, now time.Time) error {
	h, e := hex.DecodeString(m.SHA256)
	sig, f := base64.StdEncoding.DecodeString(m.Signature)
	if m.Product != Product || !Newer(m.Version, current) || m.Bytes < 1024 || m.Bytes > MaxBinary || e != nil || len(h) != 32 || hex.EncodeToString(h) != m.SHA256 || f != nil || len(key) != ed25519.PublicKeySize || m.Expires <= now.Unix() || m.Expires > now.Add(8*24*time.Hour).Unix() || !ed25519.Verify(key, m.message(), sig) {
		return fmt.Errorf("release signature, version or expiry rejected")
	}
	return nil
}
func Decode(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > 4096 {
		return m, fmt.Errorf("manifest too large")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return m, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return m, fmt.Errorf("trailing manifest")
	}
	return m, nil
}
func VerifyBinary(r io.Reader, m Manifest) error {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, m.Bytes+1))
	if e != nil || n != m.Bytes || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return fmt.Errorf("release length or SHA256 mismatch")
	}
	return nil
}
