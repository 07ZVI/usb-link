package interfaceconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeMacObservations accepts measurement scalars only; its result never
// grants device ownership, original-value restoration or network readiness.
func DecodeMacObservations(b []byte) ([]OperationTiming, error) {
	fail := func() ([]OperationTiming, error) { return nil, errors.New("USB_MAC_INTERFACE_TIMINGS_INVALID") }
	if len(b) == 0 || len(b) > 4096 || !uniqueJSON(b) {
		return fail()
	}
	var raw []map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil || len(raw) > 5 {
		return fail()
	}
	for _, fields := range raw {
		if len(fields) != 6 {
			return fail()
		}
		for _, name := range []string{"role", "kind", "calls", "failures", "disabled", "duration_ms"} {
			if v, ok := fields[name]; !ok || bytes.Equal(v, []byte("null")) {
				return fail()
			}
		}
	}
	var out []OperationTiming
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return fail()
	}
	seen := map[string]bool{}
	for _, r := range out {
		if r.Role != "mac" || r.Calls == 0 || r.Failures > r.Calls || r.Disabled > r.Calls || r.DurationMS < 0 || seen[r.Kind] {
			return fail()
		}
		switch r.Kind {
		case "dad_apply", "dad_restore", "persistent_apply", "persistent_restore", "persistent_reuse":
		default:
			return fail()
		}
		seen[r.Kind] = true
	}
	return out, nil
}
