package netconfig

import (
	"fmt"
	"regexp"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
	"unicode/utf16"
)

const hostNetClass = "{4d36e972-e325-11ce-bfc1-08002be10318}"

var hostDriverKey = regexp.MustCompile(`(?i)^\{4d36e972-e325-11ce-bfc1-08002be10318\}\\[0-9]{4}$`)
var hostGUIDText = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

type nativeHostInterface struct {
	GUID, Alias string
	Type, Index uint32
	LUID        uint64
}
type nativeHostNode struct {
	Instance, CMInstance, SetupClass, CMClass, Service, SetupDriver, CMDriver, SetupNetGUID, CMNetGUID string
	DevInst                                                                                            uint32
	ServiceType, ServiceSize, ClassType, ClassSize, DriverType, DriverSize                             uint32
	StateReadable                                                                                      bool
	Problem                                                                                            uint32
	StateError                                                                                         uint32
}

func validateNativeHostInterface(candidates []nativeHostInterface, index uint32) (nativeHostInterface, error) {
	return validateNativeWintunInterface(candidates, index, usbaddress.HostGUID, usbaddress.HostName)
}
func validateNativeWintunInterface(candidates []nativeHostInterface, index uint32, guid, alias string) (nativeHostInterface, error) {
	if !((strings.EqualFold(guid, usbaddress.HostGUID) && alias == usbaddress.HostName) || (strings.EqualFold(guid, "{A4611646-E050-4D25-B83E-633A5598F302}") && alias == "USB Link")) {
		return nativeHostInterface{}, fmt.Errorf("USB_HOST_NATIVE_EXPECTED_GUID_INVALID")
	}
	if index == 0 || len(candidates) != 1 {
		return nativeHostInterface{}, fmt.Errorf("USB_HOST_NATIVE_MAPPING_UNPROVEN")
	}
	f := candidates[0]
	if !strings.EqualFold(f.GUID, guid) || f.Alias != alias || f.Type != 53 || f.Index != index || f.LUID == 0 {
		return nativeHostInterface{}, fmt.Errorf("USB_HOST_NATIVE_MAPPING_UNPROVEN")
	}
	return f, nil
}

func validateNativeHostNode(n nativeHostNode) error {
	return validateNativeWintunNodeForGUID(n, usbaddress.HostGUID)
}
func validateNativeWintunNodeForGUID(n nativeHostNode, expectedGUID string) error {
	if e := validateNativeWintunNodeIdentityForGUID(n, expectedGUID); e != nil {
		return e
	}
	if !n.StateReadable || n.Problem != 0 || n.StateError != 0 {
		return fmt.Errorf("USB_HOST_NATIVE_NODE_STATE_UNPROVEN")
	}
	return nil
}

func validateNativeHostNodeIdentity(n nativeHostNode) error {
	return validateNativeWintunNodeIdentityForGUID(n, usbaddress.HostGUID)
}
func validateNativeWintunNodeIdentityForGUID(n nativeHostNode, expectedGUID string) error {
	if !strings.EqualFold(expectedGUID, usbaddress.HostGUID) && !strings.EqualFold(expectedGUID, "{A4611646-E050-4D25-B83E-633A5598F302}") {
		return fmt.Errorf("USB_HOST_NATIVE_EXPECTED_GUID_INVALID")
	}
	if n.Instance == "" || len(n.Instance) > 1024 || strings.ContainsAny(n.Instance, "*?\x00") || !strings.EqualFold(n.Instance, n.CMInstance) || n.DevInst == 0 {
		return fmt.Errorf("USB_HOST_NATIVE_INSTANCE_UNPROVEN")
	}
	if !strings.EqualFold(n.SetupClass, hostNetClass) || !strings.EqualFold(n.CMClass, hostNetClass) || n.ClassType != 13 || n.ClassSize != 16 {
		return fmt.Errorf("USB_HOST_NATIVE_CLASS_UNPROVEN")
	}
	if n.ServiceType != 18 || n.ServiceSize != uint32((len(utf16.Encode([]rune(n.Service)))+1)*2) || !strings.EqualFold(n.Service, "Wintun") {
		return fmt.Errorf("USB_HOST_NATIVE_SERVICE_UNPROVEN")
	}
	if n.DriverType != 18 || n.DriverSize != uint32((len(utf16.Encode([]rune(n.CMDriver)))+1)*2) || !hostDriverKey.MatchString(n.SetupDriver) || !strings.EqualFold(n.SetupDriver, n.CMDriver) {
		return fmt.Errorf("USB_HOST_NATIVE_DRIVER_KEY_UNPROVEN")
	}
	if !hostGUIDText.MatchString(n.SetupNetGUID) || !strings.EqualFold(n.SetupNetGUID, expectedGUID) || !strings.EqualFold(n.CMNetGUID, n.SetupNetGUID) {
		return fmt.Errorf("USB_HOST_NATIVE_PNP_BINDING_UNPROVEN")
	}
	return nil
}

type nativeHostNonpresentProof struct {
	PresentMatches, InstalledMatches     int
	NormalResult                         uint32
	NormalReadable, PhantomReadable      bool
	PhantomResult                        uint32
	PhantomExact                         bool
	ConfigReadable                       bool
	ConfigType, ConfigSize, Config       uint32
	CMConfigReadable                     bool
	CMConfigType, CMConfigSize, CMConfig uint32
}

func validateNativeHostNonpresent(n nativeHostNode, p nativeHostNonpresentProof) error {
	return validateNativeWintunNonpresent(n, p, usbaddress.HostGUID)
}
func validateNativeWintunNonpresent(n nativeHostNode, p nativeHostNonpresentProof, guid string) error {
	if e := validateNativeWintunNodeIdentityForGUID(n, guid); e != nil {
		return e
	}
	// CR_NO_SUCH_DEVNODE=13 is a specific lifecycle result, not permission to
	// ignore an unreadable, disabled or unhealthy present node.
	if n.StateReadable || n.StateError != 13 || n.Problem != 0 || !p.NormalReadable || p.NormalResult != 13 || !p.PhantomReadable || p.PhantomResult != 0 || !p.PhantomExact || p.PresentMatches != 0 || p.InstalledMatches != 1 {
		return fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_UNPROVEN")
	}
	// CONFIGFLAG_DISABLED and every other configuration override stay blocked.
	if !p.ConfigReadable || p.ConfigType != 4 || p.ConfigSize != 4 || p.Config != 0 || !p.CMConfigReadable || p.CMConfigType != 7 || p.CMConfigSize != 4 || p.CMConfig != p.Config {
		return fmt.Errorf("USB_HOST_NATIVE_NONPRESENT_CONFIG_UNPROVEN")
	}
	return nil
}

func validateNativeHostNonpresentTransition(a, b nativeHostInterface, x, y nativeHostNode, p, q nativeHostNonpresentProof) error {
	if _, e := validateNativeHostInterface([]nativeHostInterface{a}, a.Index); e != nil {
		return e
	}
	if _, e := validateNativeHostInterface([]nativeHostInterface{b}, a.Index); e != nil {
		return e
	}
	if a != b {
		return fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	if e := validateNativeHostNonpresent(x, p); e != nil {
		return e
	}
	if e := validateNativeHostNonpresent(y, q); e != nil {
		return e
	}
	if x != y || p != q {
		return fmt.Errorf("USB_HOST_NATIVE_NODE_CHANGED")
	}
	return nil
}

func validateNativeHostTransition(a, b nativeHostInterface, x, y nativeHostNode) error {
	if _, e := validateNativeHostInterface([]nativeHostInterface{a}, a.Index); e != nil {
		return e
	}
	if _, e := validateNativeHostInterface([]nativeHostInterface{b}, a.Index); e != nil {
		return e
	}
	if a != b {
		return fmt.Errorf("USB_HOST_NATIVE_MAPPING_CHANGED")
	}
	if e := validateNativeHostNode(x); e != nil {
		return e
	}
	if e := validateNativeHostNode(y); e != nil {
		return e
	}
	if x != y {
		return fmt.Errorf("USB_HOST_NATIVE_NODE_CHANGED")
	}
	return nil
}

func decodeNativeHostString(b []uint16, size uint32) (string, bool) {
	if size < 2 || size%2 != 0 || size > uint32(len(b)*2) {
		return "", false
	}
	x := b[:size/2]
	if x[len(x)-1] != 0 {
		return "", false
	}
	for i := 0; i < len(x)-1; i++ {
		if x[i] == 0 {
			return "", false
		}
		if x[i] >= 0xd800 && x[i] <= 0xdbff {
			if i+1 >= len(x)-1 || x[i+1] < 0xdc00 || x[i+1] > 0xdfff {
				return "", false
			}
			i++
		} else if x[i] >= 0xdc00 && x[i] <= 0xdfff {
			return "", false
		}
	}
	return string(utf16.Decode(x[:len(x)-1])), true
}
