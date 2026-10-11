package hostsecurity

import (
	"suhang/usbnet/internal/security/securitypolicy"
	"testing"
)

func TestEffectiveFirewallEvidenceNeverClaimsFullEnforcement(t *testing.T) {
	profiles := []FirewallProfile{{"Domain", true, "Block"}, {"Private", true, "Block"}, {"Public", true, "Block"}}
	e := FirewallEvidence(profiles)
	if e.State != securitypolicy.Verified || e.EnforcementVerified {
		t.Fatal(e)
	}
	profiles[2].Enabled = false
	if FirewallEvidence(profiles).State != securitypolicy.Degraded {
		t.Fatal("disabled firewall hidden")
	}
	profiles[2].Enabled = true
	profiles[2].DefaultInboundAction = "Allow"
	if FirewallEvidence(profiles).State != securitypolicy.Degraded {
		t.Fatal("open inbound hidden")
	}
	if FirewallEvidence(profiles[:2]).State != securitypolicy.Unknown {
		t.Fatal("partial inventory trusted")
	}
	profiles[2] = profiles[1]
	if FirewallEvidence(profiles).State != securitypolicy.Unknown {
		t.Fatal("duplicate profile trusted")
	}
}
