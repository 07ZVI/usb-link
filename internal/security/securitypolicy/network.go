// Package securitypolicy contains platform-independent, reviewable security
// decisions. It never opens devices, modifies Windows or runs shell commands.
package securitypolicy

type NetworkService string

const (
	FileAndSpeed      NetworkService = "file-and-speed"
	Streaming         NetworkService = "streaming"
	Discovery         NetworkService = "discovery"
	AddressAssignment NetworkService = "dhcp"
	NativeBenchmark   NetworkService = "native-benchmark"
	DeveloperUpgrade  NetworkService = "developer-upgrade"
)

// Ports is the single service catalogue for both transport adapters. No caller
// can add arbitrary ports through UI/network input. Firewall executors still
// have to bind these exceptions to the exact owned interface and peer.
func Ports(service NetworkService, protocol string) string {
	switch service {
	case FileAndSpeed:
		if protocol == "TCP" {
			return "10690"
		}
	case Streaming:
		if protocol == "TCP" {
			return "47984,47989,48010"
		}
		if protocol == "UDP" {
			return "'47998-48000',48002,48010"
		}
	case Discovery:
		if protocol == "UDP" {
			return "5353"
		}
	case AddressAssignment:
		if protocol == "UDP" {
			return "67"
		}
	case NativeBenchmark:
		if protocol == "TCP" {
			return "47772"
		}
	case DeveloperUpgrade:
		if protocol == "TCP" {
			return "47775"
		}
	}
	return ""
}

// InboundPorts preserves deployed transport exceptions during the architecture
// migration. The Mac legacy admin port is explicit rather than accidentally
// inherited by iPad. Tightening that legacy rule requires a separate migration.
func InboundPorts(transport, protocol string) string {
	if transport != "mac" && transport != "ipad" {
		return ""
	}
	if protocol == "TCP" {
		if transport == "mac" {
			return "47984,47989,47990,48010"
		}
		return Ports(FileAndSpeed, "TCP") + "," + Ports(Streaming, "TCP")
	}
	return Ports(Streaming, protocol)
}

type State string

const (
	Unknown  State = "unknown"
	Planned  State = "planned"
	Verified State = "verified"
	Degraded State = "degraded"
	Conflict State = "conflict"
)

// Evidence separates an executor receipt from OS effectiveness. A registry
// value or installed rule alone must never produce a "protected" UI badge.
type Evidence struct {
	State               State  `json:"state"`
	Code                string `json:"code"`
	Scope               string `json:"scope"`
	EnforcementVerified bool   `json:"enforcement_verified"`
}
