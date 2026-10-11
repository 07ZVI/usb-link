package interfaceconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
	"suhang/usbnet/internal/transport/ipadsession"
)

// IPadPersistentBinding is a local protected obligation, never live admission.
// Pending permits Created=0 only before a native address has been written.
type IPadPersistentBinding struct {
	Version      int              `json:"version"`
	Root         string           `json:"root"`
	Driver       string           `json:"driver"`
	Instance     string           `json:"instance"`
	SerialSHA256 string           `json:"serial_sha256"`
	Scope        Scope            `json:"scope"`
	Persistent   bool             `json:"persistent"`
	State        string           `json:"state"`
	Plan         ipadsession.Plan `json:"plan"`
}

func (v IPadPersistentBinding) valid() bool {
	if v.Version != 1 || validateScope(v.Scope) != nil || v.Scope.Role != "ipad" || !grouptrial.ValidRecoveryTarget(v.Root, v.Driver, 1, true) || !strings.HasPrefix(strings.ToUpper(v.Instance), `USB\`) || len(v.Instance) > 512 || strings.ContainsAny(v.Instance, "\x00\r\n") || !shaPattern.MatchString(v.SerialSHA256) || !v.Plan.Valid() || !strings.EqualFold(v.Plan.GUID, v.Scope.GUID) || v.Plan.LUID != v.Scope.LUID || v.Plan.Index != v.Scope.Index || v.Plan.ServerIP != "10.6.9.1" || v.Plan.HostFlags == nil {
		return false
	}
	switch v.State {
	case "pending":
		return v.Plan.Version == 5 && v.Plan.CreatedAt == 0
	case "address":
		return v.Persistent && v.Plan.Version == 5 && v.Plan.CreatedAt > 0
	case "ready":
		return v.Persistent && v.Plan.Version == 6
	case "ephemeral":
		return !v.Persistent && v.Plan.Version == 5 && v.Plan.CreatedAt > 0
	case "restoring":
		return v.Plan.Version == 5 || v.Persistent && v.Plan.Version == 6
	}
	return false
}
func decodeIPadBinding(b []byte) (IPadPersistentBinding, error) {
	var v IPadPersistentBinding
	fail := func() (IPadPersistentBinding, error) {
		return IPadPersistentBinding{}, errors.New("USB_IPAD_BINDING_INVALID")
	}
	if len(b) == 0 || len(b) > 4096 || !uniqueJSON(b) {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 9 {
		return fail()
	}
	for _, k := range []string{"version", "root", "driver", "instance", "serial_sha256", "scope", "persistent", "state", "plan"} {
		if fields[k] == nil || string(fields[k]) == "null" {
			return fail()
		}
	}
	var planFields map[string]json.RawMessage
	if json.Unmarshal(fields["plan"], &planFields) != nil {
		return fail()
	}
	for _, k := range []string{"version", "adapter_guid", "adapter_luid", "adapter_index", "server_ip", "ownership_token", "host_flags", "address_creation_intent_timestamp"} {
		if planFields[k] == nil || string(planFields[k]) == "null" {
			return fail()
		}
	}
	var flags map[string]json.RawMessage
	if json.Unmarshal(planFields["host_flags"], &flags) != nil || len(flags) != 3 {
		return fail()
	}
	for _, k := range []string{"send", "receive", "forward"} {
		if flags[k] == nil || string(flags[k]) == "null" {
			return fail()
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || !v.valid() {
		return fail()
	}
	return v, nil
}
func ipadBindingTransition(a, b IPadPersistentBinding) bool {
	if !a.valid() || !b.valid() || a.Root != b.Root || a.Driver != b.Driver || a.Instance != b.Instance || a.SerialSHA256 != b.SerialSHA256 || a.Scope != b.Scope || a.Persistent != b.Persistent || a.Plan.HostFlags == nil || b.Plan.HostFlags == nil || *a.Plan.HostFlags != *b.Plan.HostFlags {
		return false
	}
	if b.State == "restoring" {
		return reflect.DeepEqual(a.Plan, b.Plan)
	}
	if a.State == "pending" && (b.State == "address" || b.State == "ephemeral") {
		x := b.Plan
		x.CreatedAt = 0
		return reflect.DeepEqual(x, a.Plan)
	}
	if a.State == "address" && b.State == "ready" {
		x := b.Plan
		x.Version = 5
		x.AddressMode = ""
		x.PersistentSHA256 = ""
		return reflect.DeepEqual(x, a.Plan)
	}
	if a.State == "ready" && b.State == "ready" {
		return a.Plan.PersistentSHA256 == b.Plan.PersistentSHA256
	}
	return false
}

func sameIPadBinding(a, b IPadPersistentBinding) bool { return reflect.DeepEqual(a, b) }

// This new receipt records all original booleans explicitly; historical Plan
// JSON remains unchanged (its forward=false field was optional).
func (v IPadPersistentBinding) MarshalJSON() ([]byte, error) {
	type alias IPadPersistentBinding
	base, e := json.Marshal(alias(v))
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	var plan map[string]json.RawMessage
	if json.Unmarshal(base, &fields) != nil || json.Unmarshal(fields["plan"], &plan) != nil || v.Plan.HostFlags == nil {
		return nil, errors.New("USB_IPAD_BINDING_FLAGS_UNPROVEN")
	}
	flags, e := json.Marshal(struct {
		Send    bool `json:"send"`
		Receive bool `json:"receive"`
		Forward bool `json:"forward"`
	}{v.Plan.HostFlags.Send, v.Plan.HostFlags.Receive, v.Plan.HostFlags.Forward})
	if e != nil {
		return nil, e
	}
	plan["host_flags"] = flags
	fields["plan"], e = json.Marshal(plan)
	if e != nil {
		return nil, e
	}
	return json.Marshal(fields)
}

func ipadOriginalsPending(r configReceipt) bool {
	for _, v := range r.Persistent {
		if v.Scope.Role == "ipad" {
			return true
		}
	}
	for _, v := range r.DAD {
		if v.Scope.Role == "ipad" {
			return true
		}
	}
	return false
}
