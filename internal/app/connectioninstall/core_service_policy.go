package connectioninstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const CoreServiceName = "USBLinkCore"
const CoreServiceArgument = "--core-service"

type CoreServiceBinding struct {
	Version    int    `json:"version"`
	Product    string `json:"product"`
	OwnerSID   string `json:"owner_sid"`
	Executable string `json:"executable"`
	SHA256     string `json:"sha256"`
}

func parseCoreBinding(b []byte) (CoreServiceBinding, error) {
	var v CoreServiceBinding
	if len(b) > 4096 {
		return v, fmt.Errorf("CORE_BINDING_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return v, fmt.Errorf("CORE_BINDING_INVALID")
	}
	seen := map[string]bool{"version": false, "product": false, "owner_sid": false, "executable": false, "sha256": false}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		found, exists := seen[k]
		if e != nil || !ok || !exists || found {
			return v, fmt.Errorf("CORE_BINDING_INVALID")
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return v, fmt.Errorf("CORE_BINDING_INVALID")
		}
	}
	for _, ok := range seen {
		if !ok {
			return v, fmt.Errorf("CORE_BINDING_INVALID")
		}
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return v, fmt.Errorf("CORE_BINDING_INVALID")
	}
	if json.Unmarshal(b, &v) != nil || v.Version != 1 || v.Product != ProductID || v.OwnerSID == "" || v.OwnerSID == "S-1-5-18" || v.OwnerSID == "S-1-5-19" || v.OwnerSID == "S-1-5-20" || !strings.HasPrefix(v.OwnerSID, "S-1-5-21-") || len(v.SHA256) != 64 || strings.Trim(v.SHA256, "0123456789abcdef") != "" || v.Executable == "" {
		return CoreServiceBinding{}, fmt.Errorf("CORE_BINDING_INVALID")
	}
	return v, nil
}
func validateCoreServiceConfig(executable, account string, serviceType, startType uint32, delayed bool, args []string) error {
	if len(args) != 2 || args[0] != executable || args[1] != CoreServiceArgument || !strings.EqualFold(account, "LocalSystem") || serviceType != 0x10 || (startType != 2 && startType != 3) || delayed {
		return fmt.Errorf("CORE_SERVICE_CONFIG_CHANGED")
	}
	return nil
}

func coreExactFields(b []byte, fields []string) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for _, k := range fields {
		seen[k] = false
	}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		v, known := seen[k]
		if e != nil || !ok || !known || v {
			return false
		}
		seen[k] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return false
		}
	}
	for _, v := range seen {
		if !v {
			return false
		}
	}
	t, e = d.Token()
	return e == nil && t == json.Delim('}') && d.Decode(new(any)) == io.EOF
}

// The receipt is already authenticated; this is only a capability boundary for
// the legacy worker's PID/ack protocol, never an authorization by version alone.
func coreWorkerSupported(version string) bool {
	if !versionPattern.MatchString(version) {
		return false
	}
	var major, minor, patch int
	if _, e := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); e != nil {
		return false
	}
	return major > 0 || major == 0 && (minor > 8 || minor == 8 && patch >= 98)
}

type coreServiceTransition struct {
	Version  int                 `json:"version"`
	Previous *CoreServiceBinding `json:"previous"`
	Next     CoreServiceBinding  `json:"next"`
}

func parseCoreTransition(b []byte) (coreServiceTransition, error) {
	var t coreServiceTransition
	if len(b) > 4096 || !coreExactFields(b, []string{"version", "previous", "next"}) || json.Unmarshal(b, &t) != nil || t.Version != 1 {
		return t, fmt.Errorf("CORE_SERVICE_TRANSITION_INVALID")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	next, e := parseCoreBinding(fields["next"])
	if e != nil || next != t.Next {
		return t, fmt.Errorf("CORE_SERVICE_TRANSITION_INVALID")
	}
	if t.Previous != nil {
		previous, e := parseCoreBinding(fields["previous"])
		if e != nil || previous != *t.Previous || previous.OwnerSID != next.OwnerSID {
			return t, fmt.Errorf("CORE_SERVICE_TRANSITION_INVALID")
		}
	}
	return t, nil
}
