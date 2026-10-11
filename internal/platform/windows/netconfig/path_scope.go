package netconfig

import (
	"fmt"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

func macPathTargets(mac usbaddress.InterfaceProof, topology []usbaddress.InterfaceProof, mtu int) ([]usbaddress.InterfaceProof, error) {
	if mac.Index == 0 || mac.LUID == 0 || !strings.EqualFold(mac.GUID, "{A4611646-E050-4D25-B83E-633A5598F302}") || mac.Role != "" || (mtu != 1500 && mtu != 9000 && mtu != 16000) || len(topology) > 4 {
		return nil, fmt.Errorf("invalid Mac path refresh scope")
	}
	targets := []usbaddress.InterfaceProof{mac}
	for _, p := range topology {
		if p.Role == "host" {
			if len(targets) != 1 || p.Index == 0 || p.LUID == 0 || p.Created <= 0 || p.Index == mac.Index || p.LUID == mac.LUID || !strings.EqualFold(p.GUID, usbaddress.HostGUID) {
				return nil, fmt.Errorf("invalid or ambiguous USB source host")
			}
			targets = append(targets, p)
		}
	}
	return targets, nil
}
