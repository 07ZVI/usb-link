package usbgateway

import "fmt"
import "sync/atomic"
import "encoding/binary"
import "net"

// A specification is converted into a native filter without widening its
// interface condition. Applications never receive an IP-forwarding exception.
type Specification struct {
	Layer, InterfaceField, Application string
	LUID                               uint64
	Permit                             bool
	HostServiceOnly                    bool
	NativeSMBPeer                      string
	DiagnosticICMP                     string
	ForwardSource, ForwardDestination  string
	NetworkOnlyPort                    uint16
	NetworkOnlyProtocol                uint8
	NetworkOnlyLocalPort               bool
	NetworkOnlyPeer                    string
	NetworkOnlyBlock                   bool
}

var sharedHostLUID atomic.Uint64

func SetSharedHostLUID(luid uint64) { sharedHostLUID.Store(luid) }

var applicationLayers = []string{"{c38d57d1-05a7-4c33-904f-7fbceee60e82}", "{e1cd9fe7-f4b5-4273-96c0-592e487b8650}", "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}", "{a3b42c97-9f04-4672-b87e-cee9c483257f}"}

const localInterface = "{4cd62a49-59c3-4969-b7f3-bda5d32890a4}"
const forwardInterface = "{1076b8a5-6323-4c5e-9810-e8d3fc9e6136}"

var forwardingLayers = []string{"{a82acc24-4ee1-4ee1-b465-fd1d25cb10a4}", "{7b964818-19c7-493a-b71f-832c3684d28c}"}

func BasePolicy(luid uint64) ([]Specification, error) {
	if luid == 0 {
		return nil, fmt.Errorf("GATEWAY_INTERFACE_INVALID")
	}
	out := []Specification{}
	if luid == sharedHostLUID.Load() {
		for _, layer := range []string{applicationLayers[0], applicationLayers[1]} {
			out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, HostServiceOnly: true})
		}
		for _, field := range []string{localInterface, forwardInterface} {
			out = append(out, Specification{Layer: forwardingLayers[0], InterfaceField: field, LUID: luid})
		}
		return out, nil
	}
	for _, layer := range applicationLayers {
		out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid})
	}
	for _, layer := range forwardingLayers {
		for _, field := range []string{localInterface, forwardInterface} {
			out = append(out, Specification{Layer: layer, InterfaceField: field, LUID: luid})
		}
	}
	return out, nil
}
func PermitPolicy(luid uint64, path string) ([]Specification, error) {
	if luid == 0 || path == "" {
		return nil, fmt.Errorf("GATEWAY_PERMIT_INVALID")
	}
	out := []Specification{}
	if luid == sharedHostLUID.Load() {
		for _, layer := range []string{applicationLayers[0], applicationLayers[1]} {
			out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, HostServiceOnly: true, Application: path, Permit: true})
		}
		return out, nil
	}
	for _, layer := range applicationLayers {
		out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, Application: path, Permit: true})
	}
	return out, nil
}

// LocalDeliveryPolicy never grants transit between peers or towards a LAN.
// ALE still checks the application at the final local .1 endpoint.
func LocalDeliveryPolicy(luid uint64, peer string) ([]Specification, error) {
	if luid == 0 {
		return nil, fmt.Errorf("GATEWAY_INTERFACE_INVALID")
	}
	peers := []string{peer}
	if luid == sharedHostLUID.Load() {
		peers = []string{"10.6.9.2", "10.6.9.3"}
	} else if peer != "10.6.9.2" && peer != "10.6.9.3" {
		return nil, fmt.Errorf("GATEWAY_LOCAL_PEER_INVALID")
	}
	out := []Specification{}
	for _, p := range peers {
		for _, pair := range [][2]string{{p, "10.6.9.1"}, {"10.6.9.1", p}} {
			for _, field := range []string{localInterface, forwardInterface} {
				out = append(out, Specification{Layer: forwardingLayers[0], InterfaceField: field, LUID: luid, Permit: true, ForwardSource: pair[0], ForwardDestination: pair[1]})
			}
		}
	}
	return out, nil
}
func exactLocalDeliveryAddresses(s Specification) (uint32, uint32, error) {
	valid := s.ForwardDestination == "10.6.9.1" && (s.ForwardSource == "10.6.9.2" || s.ForwardSource == "10.6.9.3") || s.ForwardSource == "10.6.9.1" && (s.ForwardDestination == "10.6.9.2" || s.ForwardDestination == "10.6.9.3")
	if !valid || !s.Permit || s.Application != "" || s.Layer != forwardingLayers[0] || s.LUID == 0 || (s.InterfaceField != localInterface && s.InterfaceField != forwardInterface) || s.HostServiceOnly {
		return 0, 0, fmt.Errorf("GATEWAY_LOCAL_DELIVERY_INVALID")
	}
	return binary.BigEndian.Uint32(net.ParseIP(s.ForwardSource).To4()), binary.BigEndian.Uint32(net.ParseIP(s.ForwardDestination).To4()), nil
}

// Native SMB gets only TCP/445 to the admitted USB peer at the local .1 address.
// No all-System-app permit, IPv6, LAN destination or forwarding exception.
func NativeSMBPolicy(luid uint64, peer string) ([]Specification, error) {
	if luid == 0 {
		return nil, fmt.Errorf("GATEWAY_NATIVE_SMB_INTERFACE_INVALID")
	}
	peers := []string{peer}
	if luid == sharedHostLUID.Load() {
		peers = []string{"10.6.9.2", "10.6.9.3"}
	} else if peer != "10.6.9.2" && peer != "10.6.9.3" {
		return nil, fmt.Errorf("GATEWAY_NATIVE_SMB_PEER_INVALID")
	}
	out := []Specification{}
	for _, p := range peers {
		for _, layer := range applicationLayers[:2] {
			out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, Permit: true, NativeSMBPeer: p})
		}
	}
	return out, nil
}

func validateNativeSMBSpec(s Specification) error {
	if s.LUID == 0 || !s.Permit || s.Application != "" || s.HostServiceOnly || s.ForwardSource != "" || s.ForwardDestination != "" || s.InterfaceField != localInterface || (s.Layer != applicationLayers[0] && s.Layer != applicationLayers[1]) || (s.NativeSMBPeer != "10.6.9.2" && s.NativeSMBPeer != "10.6.9.3") {
		return fmt.Errorf("GATEWAY_NATIVE_SMB_INVALID")
	}
	return nil
}

// Diagnostic echo is fixed to the Mac USB endpoint. It never grants System
// application access, IPv6, other ICMP types, or forwarding.
func DiagnosticICMPPolicy(luid uint64) ([]Specification, error) {
	if luid == 0 {
		return nil, fmt.Errorf("GATEWAY_DIAGNOSTIC_INTERFACE_INVALID")
	}
	return []Specification{
		{Layer: applicationLayers[0], InterfaceField: localInterface, LUID: luid, Permit: true, DiagnosticICMP: "reply"},
		{Layer: applicationLayers[1], InterfaceField: localInterface, LUID: luid, Permit: true, DiagnosticICMP: "request"},
	}, nil
}
func validateDiagnosticICMPSpec(s Specification) error {
	if s.LUID == 0 || !s.Permit || s.Application != "" || s.HostServiceOnly || s.NativeSMBPeer != "" || s.ForwardSource != "" || s.ForwardDestination != "" || s.InterfaceField != localInterface || !(s.DiagnosticICMP == "reply" && s.Layer == applicationLayers[0] || s.DiagnosticICMP == "request" && s.Layer == applicationLayers[1]) {
		return fmt.Errorf("GATEWAY_DIAGNOSTIC_ICMP_INVALID")
	}
	return nil
}
