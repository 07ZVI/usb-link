// Package appfirewall owns application rules, independently of USB sessions.
package appfirewall

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const Group = "USB-Link-Application-Firewall-v1"

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Identity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Rule struct {
	ID          string   `json:"id"`
	Application Identity `json:"application"`
	Action      string   `json:"action"`
	Direction   string   `json:"direction"`
	Protocol    string   `json:"protocol"`
	Remote      string   `json:"remote"`
	Port        uint16   `json:"port"`  // Local port for inbound; remote port for outbound.
	State       string   `json:"state"` // pending/applied/error. Applied is rule read-back.
	Error       string   `json:"error,omitempty"`
}

func (r Rule) Name() string   { return "USB-Link-App-" + r.ID }
func (r Rule) Marker() string { return Group + "/" + r.ID + "/" + r.Application.SHA256 }

// Windows executable paths are absolute local paths, not UNC, ADS, device paths
// or UI-provided commands. The Windows executor additionally opens and verifies
// the file and rejects filesystem reparse points.
func ValidProgramPath(p string) bool {
	if len(p) < 7 || len(p) > 1024 || p[1] != ':' || p[2] != '\\' || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || !strings.EqualFold(p[len(p)-4:], ".exe") {
		return false
	}
	if strings.Contains(p[2:], ":") || strings.ContainsAny(p, "/*?\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(p[3:], `\`) {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (r Rule) Valid() bool {
	h, err := hex.DecodeString(r.Application.SHA256)
	if !idPattern.MatchString(r.ID) || !ValidProgramPath(r.Application.Path) || err != nil || len(h) != 32 || r.Application.Size < 64 || r.Application.Size > 1<<30 {
		return false
	}
	if r.Action != "allow" && r.Action != "block" {
		return false
	}
	if r.Direction != "outbound" && r.Direction != "inbound" {
		return false
	}
	if r.Protocol != "any" && r.Protocol != "tcp" && r.Protocol != "udp" {
		return false
	}
	if r.Protocol == "any" && r.Port != 0 {
		return false
	}
	if r.Remote != "any" {
		if a, err := netip.ParseAddr(r.Remote); err != nil {
			if _, err = netip.ParsePrefix(r.Remote); err != nil {
				return false
			}
		} else if a.Zone() != "" {
			return false
		}
	}
	return r.State == "pending" || r.State == "applied" || r.State == "error"
}

type Change struct {
	Operation string `json:"operation"`
	Rule      Rule   `json:"rule"`
}
type Store struct {
	Version int     `json:"version"`
	Rules   []Rule  `json:"rules"`
	Pending *Change `json:"pending,omitempty"`
}

func (s Store) Valid() bool {
	if s.Version != 1 || len(s.Rules) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.Rules {
		if !r.Valid() || seen[r.ID] {
			return false
		}
		seen[r.ID] = true
	}
	return s.Pending == nil || ((s.Pending.Operation == "upsert" || s.Pending.Operation == "delete") && s.Pending.Rule.Valid())
}

func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("FIREWALL_RULE_ID_INVALID")
	}
	return nil
}
