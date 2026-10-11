package securitypolicy

import (
	"fmt"
	"sort"
	"strings"
)

// Input classification supports USB admission checks and a future OS install
// gate. The primary product flow is new external-USB consent, not a global HID
// ban. USB descriptors are not cryptographic device authentication.
const (
	HIDClass      = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"
	KeyboardClass = "{4d36e96b-e325-11ce-bfc1-08002be10318}"
	MouseClass    = "{4d36e96f-e325-11ce-bfc1-08002be10318}"
)

type DeviceNode struct {
	DriverKey     string   `json:"-"` // Optional local display association, never admission.
	Name          string   `json:"name,omitempty"`
	ID            string   `json:"-"` // Instance IDs stay local, out of exported reports.
	Parent        string   `json:"-"`
	ContainerID   string   `json:"-"` // Display grouping only; never an authorization identity.
	LocationPaths []string `json:"-"` // OS topology, local display only; never used by admission.
	ClassGUID     string   `json:"class_guid"`
	Service       string   `json:"service"`
	CompatibleIDs []string `json:"-"`
}

func IsInput(n DeviceNode) bool {
	switch strings.ToLower(n.ClassGUID) {
	case HIDClass, KeyboardClass, MouseClass:
		return true
	}
	switch strings.ToLower(n.Service) {
	case "hidusb", "kbdhid", "mouhid", "hidi2c", "hidbth":
		return true
	}
	for _, id := range n.CompatibleIDs {
		id = strings.ToUpper(id)
		if strings.HasPrefix(id, `USB\CLASS_03`) || strings.HasPrefix(id, `HID_DEVICE`) {
			return true
		}
	}
	return false
}

func validInstance(id string) bool {
	if len(id) < 3 || len(id) > 200 || !strings.Contains(id, `\`) {
		return false
	}
	for _, r := range id {
		if r < 32 || strings.ContainsRune("*?\x00", r) {
			return false
		}
	}
	return true
}

type HIDPlan struct {
	Version                  int
	AllowedInstances         []string
	DeniedClasses            []string
	LayeredEvaluation        bool
	ApplyToInstalled         bool
	RecoveryKeyboardInstance string
}

func (p HIDPlan) Valid() bool {
	if p.Version != 1 || !p.LayeredEvaluation || p.ApplyToInstalled || len(p.DeniedClasses) != 3 || len(p.AllowedInstances) == 0 || len(p.AllowedInstances) > 4096 || !validInstance(p.RecoveryKeyboardInstance) {
		return false
	}
	classes := map[string]bool{}
	for _, c := range p.DeniedClasses {
		if c != HIDClass && c != KeyboardClass && c != MouseClass {
			return false
		}
		if classes[c] {
			return false
		}
		classes[c] = true
	}
	seen := map[string]bool{}
	for _, id := range p.AllowedInstances {
		if !validInstance(id) || seen[strings.ToUpper(id)] {
			return false
		}
		seen[strings.ToUpper(id)] = true
	}
	return seen[strings.ToUpper(p.RecoveryKeyboardInstance)]
}

// PlanHID preserves all currently present input devnodes (including built-in
// input), not just a guessed keyboard VID/PID. The backend must validate Windows
// edition/build, a complete fresh inventory, conflicting policies and recovery
// access before applying this plan. Existing installs must not be retroactively
// disabled. This gate alone cannot police every reconnect of installed devices.
// An incomplete scan is never an empty list.
func PlanHID(nodes []DeviceNode, complete bool) (HIDPlan, error) {
	p := HIDPlan{Version: 1, DeniedClasses: []string{HIDClass, KeyboardClass, MouseClass}, LayeredEvaluation: true, ApplyToInstalled: false}
	if !complete || len(nodes) == 0 || len(nodes) > 4096 {
		return HIDPlan{}, fmt.Errorf("HID_INVENTORY_UNAVAILABLE")
	}
	seen := map[string]bool{}
	keyboard := false
	for _, n := range nodes {
		if !IsInput(n) {
			continue
		}
		id := strings.ToUpper(n.ID)
		if !validInstance(id) {
			return HIDPlan{}, fmt.Errorf("HID_INSTANCE_INVALID")
		}
		if strings.EqualFold(n.ClassGUID, KeyboardClass) {
			keyboard = true
			if p.RecoveryKeyboardInstance == "" {
				p.RecoveryKeyboardInstance = id
			}
		}
		if !seen[id] {
			seen[id] = true
			p.AllowedInstances = append(p.AllowedInstances, id)
		}
	}
	if !keyboard || len(p.AllowedInstances) == 0 {
		return HIDPlan{}, fmt.Errorf("HID_RECOVERY_KEYBOARD_UNCONFIRMED")
	}
	sort.Strings(p.AllowedInstances)
	return p, nil
}

type DeviceVerdict struct {
	Admit      bool   `json:"admit_usb_network"`
	Code       string `json:"code"`
	InputNodes int    `json:"input_nodes"`
}

// USBAdmission follows exact parent links. A separate keyboard sharing an
// Apple VID, a USB hub or a similar instance-ID prefix is outside this scope.
// This protects our network session, not Windows' input delivery path.
func USBAdmission(root string, nodes []DeviceNode, complete bool) DeviceVerdict {
	v := DeviceVerdict{Code: "USB_SECURITY_INVENTORY_UNAVAILABLE"}
	if !complete || !validInstance(root) || len(nodes) == 0 || len(nodes) > 4096 {
		return v
	}
	root = strings.ToUpper(root)
	index := make(map[string]DeviceNode, len(nodes))
	for _, n := range nodes {
		id := strings.ToUpper(n.ID)
		if !validInstance(id) {
			return v
		}
		if _, duplicate := index[id]; duplicate {
			return v
		}
		index[id] = n
	}
	if _, ok := index[root]; !ok {
		v.Code = "USB_SECURITY_ROOT_ABSENT"
		return v
	}
	for id, n := range index {
		if !IsInput(n) {
			continue
		}
		seen := map[string]bool{}
		for hops := 0; id != ""; hops++ {
			if hops >= 64 || seen[id] {
				return DeviceVerdict{Code: "USB_SECURITY_ANCESTRY_UNAVAILABLE"}
			}
			seen[id] = true
			if id == root {
				v.InputNodes++
				break
			}
			parent, ok := index[id]
			if !ok {
				break
			}
			id = strings.ToUpper(parent.Parent)
		}
	}
	if v.InputNodes != 0 {
		v.Code = "USB_UNEXPECTED_HID_INTERFACE"
		return v
	}
	v.Admit, v.Code = true, "USB_NETWORK_INPUT_CLASS_ABSENT"
	return v
}
