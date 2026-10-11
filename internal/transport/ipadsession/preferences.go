package ipadsession

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

type DeviceGrant struct {
	Identity string `json:"identity_sha256"`
	Key      string `json:"device_public_key_sha256"`
	Product  string `json:"product"`
}
type Preferences struct {
	Version        int              `json:"version"`
	Startup        bool             `json:"startup"`
	IndependentUSB bool             `json:"independent_usb"`
	Devices        []DeviceGrant    `json:"devices"`
	USBDevices     []USBDeviceGrant `json:"usb_devices,omitempty"`
}

func DefaultPreferences() Preferences { return Preferences{Version: 2, IndependentUSB: true} }
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (p Preferences) Valid() bool {
	if (p.Version != 1 && p.Version != 2) || len(p.Devices) > 32 || len(p.USBDevices) > 32 || (p.Version == 1 && len(p.USBDevices) != 0) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range p.Devices {
		if !validDigest(g.Identity) || !validDigest(g.Key) || g.Product != "iPad13,16" || seen[g.Identity] {
			return false
		}
		seen[g.Identity] = true
	}
	seenUSB := map[string]bool{}
	for _, g := range p.USBDevices {
		if !g.Valid() || seenUSB[g.Identity] {
			return false
		}
		seenUSB[g.Identity] = true
	}
	return true
}
func ParsePreferences(b []byte) (Preferences, error) {
	var p Preferences
	if len(b) > 32768 {
		return p, fmt.Errorf("preferences too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || !p.Valid() {
		return p, fmt.Errorf("preferences invalid")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return p, fmt.Errorf("preferences trailing data")
	}
	p.Version = 2 // Preserve existing choices and legacy records without treating them as USB grants.
	return p, nil
}
func DeviceIdentity(serial string) string {
	s := sha256.Sum256([]byte("Suhang iPad USB identity v1\x00" + serial))
	return hex.EncodeToString(s[:])
}
func (p Preferences) Trusted(identity, key, product string, authenticated bool) bool {
	if !authenticated || !validDigest(identity) || !validDigest(key) {
		return false
	}
	for _, g := range p.Devices {
		if subtle.ConstantTimeCompare([]byte(g.Identity), []byte(identity)) == 1 && subtle.ConstantTimeCompare([]byte(g.Key), []byte(key)) == 1 && g.Product == product {
			return true
		}
	}
	return false
}
func (p *Preferences) Remember(g DeviceGrant, authenticated bool) error {
	if !authenticated || !validDigest(g.Identity) || !validDigest(g.Key) || g.Product != "iPad13,16" {
		return fmt.Errorf("authenticated device required")
	}
	for i, old := range p.Devices {
		if old.Identity == g.Identity {
			p.Devices[i] = g
			return nil
		}
	}
	if len(p.Devices) >= 32 {
		return fmt.Errorf("paired device limit")
	}
	p.Devices = append(p.Devices, g)
	return nil
}
