package interfaceconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// The original receipt is immutable. This distinct transaction records only
// the current factory mapping, never replacement originals. Attempt is durable
// before Create; a crash there cannot adopt a same-GUID healthy interface.
type secondaryBinding struct {
	Version        int    `json:"version"`
	OriginalSHA256 string `json:"original_sha256"`
	OriginalScope  Scope  `json:"original_scope"`
	CurrentScope   Scope  `json:"current_scope"`
	Instance       string `json:"instance"`
	State          string `json:"state"`
	Attempt        string `json:"attempt"`
	Ticks          uint64 `json:"ticks"`
	Created        int64  `json:"created"`
	Mode           string `json:"mode"`
}

func decodeSecondaryBinding(b []byte) (secondaryBinding, error) {
	var v secondaryBinding
	fail := func() (secondaryBinding, error) {
		return secondaryBinding{}, errors.New("USB_SECONDARY_BINDING_INVALID")
	}
	if len(b) == 0 || len(b) > 4096 || !uniqueJSON(b) {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 10 {
		return fail()
	}
	for _, k := range []string{"version", "original_sha256", "original_scope", "current_scope", "instance", "state", "attempt", "ticks", "created", "mode"} {
		if _, ok := fields[k]; !ok {
			return fail()
		}
	}
	// The field count is deliberately exact; unknown or omitted members are not
	// inferred from zero values (including a missing creation phase).
	if len(fields) != 10 {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Version != 1 || !shaPattern.MatchString(v.OriginalSHA256) || validateScope(v.OriginalScope) != nil || validateScope(v.CurrentScope) != nil || v.OriginalScope.Role != "mac" || v.CurrentScope.Role != "mac" || !strings.EqualFold(v.OriginalScope.GUID, v.CurrentScope.GUID) || v.Instance == "" || len(v.Instance) > 1024 || strings.ContainsAny(v.Instance, "*?\x00") {
		return fail()
	}
	switch v.State {
	case "ready", "closed":
		if v.Created <= 0 || (v.Mode != "legacy" && v.Mode != "persistent") || v.Attempt != "" || v.Ticks != 0 {
			return fail()
		}
	case "attempt", "restore_attempt":
		if v.Created != 0 || v.Mode != "" || len(v.Attempt) != 32 || !lowerHex(v.Attempt) || v.Ticks == 0 {
			return fail()
		}
	case "mapped", "restore_mapped", "restored":
		if v.Created != 0 || v.Mode != "" || len(v.Attempt) != 32 || !lowerHex(v.Attempt) || v.Ticks == 0 {
			return fail()
		}
	default:
		return fail()
	}
	return v, nil
}
func lowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func secondaryTransition(a, b secondaryBinding) error {
	bad := func() error { return errors.New("USB_SECONDARY_BINDING_TRANSITION_UNPROVEN") }
	for _, v := range []secondaryBinding{a, b} {
		x, _ := json.Marshal(v)
		if _, e := decodeSecondaryBinding(x); e != nil {
			return bad()
		}
	}
	if a.Version != b.Version || a.OriginalSHA256 != b.OriginalSHA256 || a.OriginalScope != b.OriginalScope || a.Instance != b.Instance {
		return bad()
	}
	switch {
	case a.State == "ready" && b.State == "ready":
		if a.CurrentScope.LUID == b.CurrentScope.LUID && strings.EqualFold(a.CurrentScope.GUID, b.CurrentScope.GUID) && a.CurrentScope.Role == b.CurrentScope.Role && (b.Created == a.Created && b.Mode == a.Mode || b.Mode == "persistent") {
			return nil
		}
	case a.State == "ready" && b.State == "closed":
		if a.CurrentScope == b.CurrentScope && a.Created == b.Created && a.Mode == b.Mode {
			return nil
		}
	case a.State == "closed" && b.State == "attempt":
		if a.CurrentScope == b.CurrentScope {
			return nil
		}
	case a.State == "attempt" && b.State == "mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	case a.State == "mapped" && b.State == "ready":
		if a.CurrentScope == b.CurrentScope {
			return nil
		}
	case a.State == "closed" && b.State == "restore_attempt":
		if a.CurrentScope == b.CurrentScope {
			return nil
		}
	case a.State == "restore_attempt" && b.State == "restore_mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	case a.State == "restore_mapped" && b.State == "restored":
		if a.CurrentScope == b.CurrentScope && a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	}
	return bad()
}
func secondaryCurrentMatches(v secondaryBinding, o persistentOriginal, s Scope) bool {
	return (v.State == "ready" || v.State == "mapped") && v.OriginalScope == o.Scope && v.CurrentScope == s && v.OriginalSHA256 == persistentDigest(o)
}

func persistentDigest(o persistentOriginal) string {
	b, _ := json.Marshal(o)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func secondaryProjectionMatches(v secondaryBinding, o persistentOriginal, s Scope) bool {
	return v.State == "ready" && v.OriginalScope == o.Scope && v.OriginalSHA256 == persistentDigest(o) && v.CurrentScope.Role == s.Role && v.CurrentScope.LUID == s.LUID && strings.EqualFold(v.CurrentScope.GUID, s.GUID)
}
