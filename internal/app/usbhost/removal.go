package usbhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// This sidecar does not replace or extend the original address journal. It
// retains the exact interrupted deletion obligation, including unknown flags.
type removalIntent struct {
	Version       int    `json:"version"`
	JournalSHA256 string `json:"journal_sha256"`
	Instance      string `json:"instance"`
	Ticks         uint64 `json:"system_ticks"`
	State         string `json:"state"`
}

func journalDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func decodeRemovalIntent(b []byte) (removalIntent, error) {
	var p removalIntent
	// Reject duplicate keys as well as unknown/missing fields; a later state
	// value must not replace the durable interrupted-deletion obligation.
	fields := json.NewDecoder(bytes.NewReader(b))
	start, e := fields.Token()
	if len(b) > 2048 || e != nil || start != json.Delim('{') {
		return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
	}
	required := map[string]bool{"version": false, "journal_sha256": false, "instance": false, "system_ticks": false, "state": false}
	for fields.More() {
		key, e := fields.Token()
		name, ok := key.(string)
		seen, known := required[name]
		if e != nil || !ok || !known || seen {
			return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
		}
		required[name] = true
		var value json.RawMessage
		if fields.Decode(&value) != nil {
			return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
		}
	}
	for _, seen := range required {
		if !seen {
			return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 2048 || d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version != 1 || len(p.JournalSHA256) != 64 || p.Ticks == 0 || p.Instance == "" || len(p.Instance) > 1024 || strings.ContainsAny(p.Instance, "*?\x00") {
		return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
	}
	if _, e := hex.DecodeString(p.JournalSHA256); e != nil {
		return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
	}
	switch p.State {
	case "intent", "restart_required", "flags_unreadable", "complete":
	default:
		return p, fmt.Errorf("USB_HOST_REMOVAL_INTENT_INVALID")
	}
	return p, nil
}

func removalRecoveryGate(p removalIntent, b []byte, journalPresent bool, ticks uint64) error {
	if journalPresent {
		if _, e := decodeJournal(b); e != nil || journalDigest(b) != p.JournalSHA256 {
			return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_CHANGED")
		}
	} else if p.State != "complete" {
		return fmt.Errorf("USB_HOST_REMOVAL_JOURNAL_MISSING")
	}
	if p.State != "complete" && (ticks == 0 || ticks >= p.Ticks) {
		return fmt.Errorf("USB_HOST_REMOVAL_REBOOT_UNPROVEN")
	}
	return nil
}
