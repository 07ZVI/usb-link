package interfaceconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

// An identity is an immutable recovery obligation, never live authorization.
// Instance is the typed Wintun/UsbNcm node, not an alias or diagnostic hint.
type OwnedDADIdentity struct {
	Scope        Scope  `json:"scope"`
	Instance     string `json:"instance"`
	RootInstance string `json:"root_instance"`
	Driver       string `json:"driver"`
	Serial       string `json:"serial"`
}
type ownedDADOriginal struct {
	Identity OwnedDADIdentity `json:"identity"`
	Original uint32           `json:"original"`
}
type ownedDADLedger struct {
	Version          int                `json:"version"`
	RestoreRequested bool               `json:"restore_requested"`
	Originals        []ownedDADOriginal `json:"originals"`
}

var ownedDADSerial = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validOwnedDADIdentity(v OwnedDADIdentity) bool {
	if validateScope(v.Scope) != nil || len(v.Instance) > 512 || len(v.Instance) < 3 || strings.ContainsAny(v.Instance, "*?\x00\r\n") {
		return false
	}
	if v.Scope.Role == "ipad" {
		if strings.EqualFold(v.Scope.GUID, HostGUID) || strings.EqualFold(v.Scope.GUID, MacGUID) || !grouptrial.ValidRecoveryTarget(v.RootInstance, v.Driver, 1, true) {
			return false
		}
		return strings.HasPrefix(strings.ToUpper(v.Instance), `USB\`) && strings.HasPrefix(strings.ToUpper(v.RootInstance), `USB\`) && len(v.RootInstance) <= 512 && !strings.ContainsAny(v.RootInstance, "*?\x00\r\n") && len(v.Driver) > 0 && len(v.Driver) <= 256 && !strings.ContainsAny(v.Driver, "*?\x00\r\n") && ownedDADSerial.MatchString(v.Serial)
	}
	return v.RootInstance == "" && v.Driver == "" && v.Serial == ""
}

// Index can change after a reboot. LUID, GUID, role and typed node cannot.
func sameOwnedDADLifecycle(a, b OwnedDADIdentity) bool {
	a.Scope.Index = 0
	b.Scope.Index = 0
	return a == b
}
func decodeOwnedDADLedger(b []byte) (ownedDADLedger, error) {
	var v ownedDADLedger
	bad := func() (ownedDADLedger, error) { return v, errors.New("USB_OWNED_DAD_RECEIPT_INVALID") }
	if len(b) == 0 || len(b) > 16384 || !uniqueJSON(b) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Version != 1 || len(v.Originals) > 16 {
		return bad()
	}
	// Missing zero-valued fields must not silently become a valid original.
	var raw struct {
		Version          *int  `json:"version"`
		RestoreRequested *bool `json:"restore_requested"`
		Originals        []struct {
			Identity json.RawMessage `json:"identity"`
			Original *uint32         `json:"original"`
		} `json:"originals"`
	}
	if json.Unmarshal(b, &raw) != nil || raw.Version == nil || raw.RestoreRequested == nil || raw.Originals == nil {
		return bad()
	}
	seen := map[string]bool{}
	for i, o := range v.Originals {
		if !validOwnedDADIdentity(o.Identity) || o.Original > 32 || raw.Originals[i].Original == nil {
			return bad()
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw.Originals[i].Identity, &fields) != nil || len(fields) != 5 {
			return bad()
		}
		for _, k := range []string{"scope", "instance", "root_instance", "driver", "serial"} {
			if value, ok := fields[k]; !ok || string(value) == "null" {
				return bad()
			}
		}
		key := strings.ToUpper(o.Identity.Scope.GUID)
		if seen[key] {
			return bad()
		}
		seen[key] = true
	}
	return v, nil
}
func sameOwnedDADLedger(a, b ownedDADLedger) bool { return reflect.DeepEqual(a, b) }
func sameOwnedDADBaselines(a, b ownedDADLedger) bool {
	if a.Version != b.Version || a.RestoreRequested && !b.RestoreRequested {
		return false
	}
	for _, x := range a.Originals {
		for _, y := range b.Originals {
			if strings.EqualFold(x.Identity.Scope.GUID, y.Identity.Scope.GUID) && x != y {
				return false
			}
		}
	}
	return true
}
func ownedDADAdmission(v ownedDADLedger, id OwnedDADIdentity, current uint32) (int, error) {
	if !validOwnedDADIdentity(id) || current > 32 {
		return -1, errors.New("USB_OWNED_DAD_SOURCE_UNPROVEN")
	}
	if v.RestoreRequested {
		return -1, errors.New("USB_OWNED_DAD_UNINSTALL_PENDING")
	}
	for i, o := range v.Originals {
		if strings.EqualFold(o.Identity.Scope.GUID, id.Scope.GUID) {
			if !sameOwnedDADLifecycle(o.Identity, id) || (current != 0 && current != o.Original) {
				return -1, errors.New("USB_OWNED_DAD_LIFECYCLE_CHANGED")
			}
			return i, nil
		}
	}
	if len(v.Originals) >= 16 {
		return -1, errors.New("USB_OWNED_DAD_LEDGER_FULL")
	}
	return -1, nil
}
