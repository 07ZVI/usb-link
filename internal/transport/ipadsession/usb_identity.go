package ipadsession

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// This is a user-selected USB identifier match, not certificate authentication.
type USBDeviceGrant struct {
	Identity    string `json:"usb_identity_sha256"`
	Fingerprint string `json:"usb_layout_sha256"`
	PID         string `json:"pid"`
}

var stableUSBSerial = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

func USBGrant(root, pid, layout string) USBDeviceGrant {
	parts := strings.Split(strings.ToUpper(root), `\`)
	if len(parts) != 3 || parts[0] != "USB" || parts[1] != "VID_05AC&PID_"+pid || !stableUSBSerial.MatchString(parts[2]) || (pid != "12AB" && pid != "1903") || layout == "" {
		return USBDeviceGrant{}
	}
	i := sha256.Sum256([]byte("Suhang USB info identity v1\x00" + parts[1] + "\x00" + parts[2]))
	f := sha256.Sum256([]byte("Suhang USB info layout v1\x00" + pid + "\x00" + layout))
	return USBDeviceGrant{hex.EncodeToString(i[:]), hex.EncodeToString(f[:]), pid}
}
func (g USBDeviceGrant) Valid() bool {
	return validDigest(g.Identity) && validDigest(g.Fingerprint) && (g.PID == "12AB" || g.PID == "1903")
}
func (p Preferences) TrustedUSB(g USBDeviceGrant) bool {
	if !g.Valid() {
		return false
	}
	for _, old := range p.USBDevices {
		if old == g {
			return true
		}
	}
	return false
}
func (p *Preferences) RememberUSB(g USBDeviceGrant) bool {
	if !g.Valid() {
		return false
	}
	p.Version = 2
	for i, old := range p.USBDevices {
		if old.Identity == g.Identity {
			p.USBDevices[i] = g
			return true
		}
	}
	if len(p.USBDevices) >= 32 {
		return false
	}
	p.USBDevices = append(p.USBDevices, g)
	return true
}
