// Package hostsecurity exposes OS evidence separately from connection state.
// Host policy is permanent across USB sessions and must never be cleaned up by
// an individual transport disconnect.
package hostsecurity

import "suhang/usbnet/internal/security/securitypolicy"

type FirewallProfile struct {
	Name                 string `json:"Name"`
	Enabled              bool   `json:"Enabled"`
	DefaultInboundAction string `json:"DefaultInboundAction"`
}

func FirewallEvidence(profiles []FirewallProfile) securitypolicy.Evidence {
	e := securitypolicy.Evidence{State: securitypolicy.Unknown, Code: "HOST_FIREWALL_UNAVAILABLE", Scope: "host"}
	if len(profiles) != 3 {
		return e
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		if (p.Name != "Domain" && p.Name != "Private" && p.Name != "Public") || seen[p.Name] {
			return e
		}
		seen[p.Name] = true
		if !p.Enabled || p.DefaultInboundAction != "Block" {
			return securitypolicy.Evidence{State: securitypolicy.Degraded, Code: "HOST_FIREWALL_DISABLED_OR_INBOUND_OPEN", Scope: "host"}
		}
	}
	// This confirms enabled profiles, not the safety of every merged rule.
	return securitypolicy.Evidence{State: securitypolicy.Verified, Code: "HOST_FIREWALL_PROFILES_ENABLED", Scope: "host"}
}
