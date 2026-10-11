// Package macalias restricts fixed-address maintenance to Apple device-side NCM.
package macalias

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

type Interface struct {
	Controller, Name string
	Connected        bool
}
type Address struct{ Interface, IP, Mask string }
type Owned struct{ Controller, Name string }
type Action struct {
	Add       bool
	Interface string
	IP        string
}

var controllerRE = regexp.MustCompile(`^\+-o AppleT8103USBXDCI@([0-9]+)  <class AppleT8103USBXDCI,`)
var nameRE = regexp.MustCompile(`"BSD Name" = "((?:en|anpi)[0-9]+)"`)

// A sibling node closes the previous scope. Neither auxiliary NCM nor an
// arbitrary later BSD Name can be mistaken for the primary data interface.
func Parse(text string) ([]Interface, error) {
	var out []Interface
	controller, connected, primary, driver := "", false, false, false
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if m := controllerRE.FindStringSubmatch(line); m != nil {
			controller = m[1]
			connected = false
			primary = false
			driver = false
			continue
		}
		if controller == "" {
			continue
		}
		if strings.Contains(line, `"CurrentState" =`) {
			connected = strings.Contains(line, `"OnBus"=Yes`) && strings.Contains(line, `"DeviceState"="Configured"`)
		}
		if strings.HasPrefix(line, "  +-o ") {
			primary = strings.HasPrefix(line, "  +-o AppleUSBNCMData@1  <class IOUSBDeviceInterface,")
			driver = false
		}
		if primary && strings.Contains(line, "+-o AppleUSBDeviceNCM11Data  <class AppleUSBDeviceNCM11Data,") {
			driver = true
		}
		if primary && driver {
			if m := nameRE.FindStringSubmatch(line); m != nil {
				if seen[controller] || seen["name:"+m[1]] {
					return nil, fmt.Errorf("ambiguous Apple NCM mapping")
				}
				seen[controller] = true
				seen["name:"+m[1]] = true
				out = append(out, Interface{controller, m[1], connected})
				primary = false
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("supported Apple device-side NCM not found")
	}
	return out, nil
}
func Addresses(text string) []Address {
	var out []Address
	name := ""
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if p := strings.Index(line, ":"); p > 0 {
				name = line[:p]
			}
		}
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "inet" && f[2] == "netmask" {
			out = append(out, Address{name, f[1], f[3]})
		}
	}
	return out
}
func Plan(interfaces []Interface, addresses []Address, owned []Owned) ([]Action, error) {
	return PlanForProfile(interfaces, addresses, owned, usbaddress.Legacy)
}
func PlanForProfile(interfaces []Interface, addresses []Address, owned []Owned, profile string) ([]Action, error) {
	plan, e := usbaddress.Lookup(profile)
	if e != nil {
		return nil, e
	}
	peer := plan.Peer
	prefix := strings.TrimSuffix(peer, "2")
	if profile == usbaddress.Legacy {
		prefix = "10.77.0."
	}
	peerValue := binary.BigEndian.Uint32(net.ParseIP(peer).To4())
	target := ""
	mapped := map[string]string{}
	own := map[string]bool{}
	for _, v := range interfaces {
		mapped[v.Name] = v.Controller
		if v.Connected {
			if target != "" {
				return nil, fmt.Errorf("multiple connected device controllers")
			}
			target = v.Name
		}
	}
	for _, v := range owned {
		if c, ok := mapped[v.Name]; !ok || c != v.Controller {
			return nil, fmt.Errorf("owned interface mapping changed: %s", v.Name)
		}
		own[v.Name] = true
	}
	for _, a := range addresses {
		if a.Interface != target && !own[a.Interface] {
			ip := net.ParseIP(a.IP).To4()
			mask, err := strconv.ParseUint(strings.TrimPrefix(a.Mask, "0x"), 16, 32)
			if ip == nil || err != nil {
				return nil, fmt.Errorf("cannot validate existing IPv4 mask on %s", a.Interface)
			}
			if uint32(mask) != 0 && binary.BigEndian.Uint32(ip)&uint32(mask) == peerValue&uint32(mask) {
				return nil, fmt.Errorf("existing subnet overlaps USB address on %s", a.Interface)
			}
		}
		if strings.HasPrefix(a.IP, prefix) && !(own[a.Interface] && a.IP == peer && a.Mask == "0xffffff00") {
			return nil, fmt.Errorf("existing address conflicts on %s", a.Interface)
		}
		if a.Interface == target && !strings.HasPrefix(a.IP, "169.254.") && !(own[a.Interface] && a.IP == peer && a.Mask == "0xffffff00") {
			return nil, fmt.Errorf("preserve existing IPv4 on %s", target)
		}
	}
	var actions []Action
	exists := false
	for _, a := range addresses {
		if own[a.Interface] && a.IP == peer {
			if a.Interface != target {
				actions = append(actions, Action{false, a.Interface, peer})
			} else {
				exists = true
			}
		}
	}
	if target != "" && !exists {
		actions = append(actions, Action{true, target, peer})
	}
	return actions, nil
}

// Migration is limited to addresses on previously owned, unchanged controllers.
// It tolerates a partial earlier migration, without adopting an unknown alias.
func MigrationPlan(v []Interface, a []Address, owned []Owned) ([]Action, error) {
	mapped := map[string]string{}
	for _, i := range v {
		mapped[i.Name] = i.Controller
	}
	own := map[string]bool{}
	for _, o := range owned {
		if mapped[o.Name] != o.Controller {
			return nil, fmt.Errorf("owned mapping changed")
		}
		own[o.Name] = true
	}
	var remove []Action
	var remaining []Address
	for _, ip := range a {
		if ip.IP == "10.77.0.1" && own[ip.Interface] && ip.Mask == "0xffffff00" {
			remove = append(remove, Action{false, ip.Interface, ip.IP})
		} else {
			remaining = append(remaining, ip)
		}
	}
	next, e := PlanForProfile(v, remaining, owned, usbaddress.Unified)
	if e != nil {
		return nil, e
	}
	return append(remove, next...), nil
}
