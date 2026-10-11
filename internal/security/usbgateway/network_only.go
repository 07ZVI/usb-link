package usbgateway

import (
	"fmt"
	"strings"
)

func appleSyncApplication(path string) bool {
	name := strings.ToLower(path[strings.LastIndexAny(path, `/\`)+1:])
	switch name {
	case "itunes.exe", "appledevices.exe", "applemobiledeviceprocess.exe", "applemobiledeviceservice.exe":
		return true
	}
	return false
}

// All mDNS on the iPad's physical USB interface is blocked. WFP cannot inspect
// DNS service-name payloads without a callout driver; the broader UDP/5353
// restriction is explicit. Nothing on the Mac or LAN interface is changed.
func IPadNetworkOnlyPolicy(luid, host uint64, applications []string) ([]Specification, error) {
	if luid == 0 || luid == host {
		return nil, fmt.Errorf("network-only physical interface invalid")
	}
	out := []Specification{}
	for _, layer := range applicationLayers {
		for _, local := range []bool{false, true} {
			for _, pair := range []struct {
				port     uint16
				protocol uint8
			}{{62078, 6}, {5353, 17}} {
				out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, NetworkOnlyBlock: true, NetworkOnlyPort: pair.port, NetworkOnlyProtocol: pair.protocol, NetworkOnlyLocalPort: local})
			}
		}
		for _, path := range applications {
			if appleSyncApplication(path) {
				out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: luid, NetworkOnlyBlock: true, Application: path})
			}
		}
	}
	if host != 0 {
		for _, layer := range applicationLayers[:2] {
			for _, local := range []bool{false, true} {
				out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: host, NetworkOnlyBlock: true, NetworkOnlyPeer: "10.6.9.3", NetworkOnlyPort: 62078, NetworkOnlyProtocol: 6, NetworkOnlyLocalPort: local})
			}
			for _, path := range applications {
				if appleSyncApplication(path) {
					out = append(out, Specification{Layer: layer, InterfaceField: localInterface, LUID: host, NetworkOnlyBlock: true, NetworkOnlyPeer: "10.6.9.3", Application: path})
				}
			}
		}
	}
	return out, nil
}

func validateNetworkOnlySpec(s Specification) error {
	validLayer := false
	for _, layer := range applicationLayers {
		if s.Layer == layer {
			validLayer = true
		}
	}
	port := s.NetworkOnlyPort == 62078 && s.NetworkOnlyProtocol == 6 || s.NetworkOnlyPort == 5353 && s.NetworkOnlyProtocol == 17
	app := s.Application != "" && appleSyncApplication(s.Application) && s.NetworkOnlyPort == 0 && s.NetworkOnlyProtocol == 0
	if port && s.Application != "" {
		return fmt.Errorf("network-only port rule must not be an application grant")
	}
	if !s.NetworkOnlyBlock || s.Permit || s.LUID == 0 || !validLayer || s.InterfaceField != localInterface || s.HostServiceOnly || s.NativeSMBPeer != "" || s.DiagnosticICMP != "" || s.ForwardSource != "" || s.ForwardDestination != "" || (!port && !app) || (s.NetworkOnlyPeer != "" && (s.NetworkOnlyPeer != "10.6.9.3" || s.Layer != applicationLayers[0] && s.Layer != applicationLayers[1])) {
		return fmt.Errorf("network-only restriction invalid")
	}
	return nil
}
