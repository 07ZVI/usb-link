package usbhost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// A creation transaction is separate from the legacy removal obligation. The
// old completed address journal is retained through both unknown creation and
// mapped/no-address phases. Only ready contains a proven replacement journal.
type recreateTransaction struct {
	Version      int     `json:"version"`
	OldSHA256    string  `json:"old_sha256"`
	OriginalLUID uint64  `json:"original_luid"`
	Instance     string  `json:"instance"`
	Token        string  `json:"attempt_token"`
	Ticks        uint64  `json:"system_ticks"`
	State        string  `json:"state"`
	Next         journal `json:"next"`
}

func exactJSONFields(b []byte, required []string) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(required))
	for _, k := range required {
		seen[k] = false
	}
	for d.More() {
		t, e := d.Token()
		k, ok := t.(string)
		s, known := seen[k]
		if e != nil || !ok || !known || s {
			return false
		}
		seen[k] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
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

func decodeRecreateTransaction(b []byte) (recreateTransaction, error) {
	var t recreateTransaction
	fail := func() (recreateTransaction, error) {
		return recreateTransaction{}, fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_INVALID")
	}
	if len(b) > 4096 || !exactJSONFields(b, []string{"version", "old_sha256", "original_luid", "instance", "attempt_token", "system_ticks", "state", "next"}) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&t) != nil || d.Decode(new(any)) != io.EOF || t.Version != 1 || t.OriginalLUID == 0 || t.Ticks == 0 || len(t.OldSHA256) != 64 || len(t.Token) != 24 || t.Instance == "" || len(t.Instance) > 1024 || strings.ContainsAny(t.Instance, "*?\x00") {
		return fail()
	}
	if _, e := hex.DecodeString(t.OldSHA256); e != nil {
		return fail()
	}
	if _, e := hex.DecodeString(t.Token); e != nil {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || !exactJSONFields(fields["next"], []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token"}) {
		return fail()
	}
	switch t.State {
	case "attempt", "closing":
		if t.Next != (journal{}) {
			return fail()
		}
	case "mapped", "ready":
		j, _ := json.Marshal(t.Next)
		if _, e := decodeJournal(j); e != nil || t.Next.Index == 0 || t.Next.LUID == 0 || t.Next.Token != t.Token {
			return fail()
		}
		if t.State == "mapped" && t.Next.Created != 0 {
			return fail()
		}
		if t.State == "ready" && (t.Next.Created < t.Next.Planned || t.Next.Created-t.Next.Planned > 150000000) {
			return fail()
		}
	default:
		return fail()
	}
	return t, nil
}

func validateRecreateTransition(old, next recreateTransaction) error {
	for _, t := range []recreateTransaction{old, next} {
		b, e := json.Marshal(t)
		if e != nil {
			return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_INVALID")
		}
		if _, e = decodeRecreateTransaction(b); e != nil {
			return e
		}
	}
	if old.State == "ready" && next.State == "closing" {
		b, _ := json.Marshal(old.Next)
		if next.Version == old.Version && next.OldSHA256 == journalDigest(b) && next.OriginalLUID == old.Next.LUID && next.Instance == old.Instance && next.Token == old.Token && next.Ticks == old.Ticks {
			return nil
		}
		return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
	}
	if old.Version != next.Version || old.OldSHA256 != next.OldSHA256 || old.OriginalLUID != next.OriginalLUID || old.Instance != next.Instance || old.Token != next.Token || old.Ticks != next.Ticks {
		return fmt.Errorf("USB_HOST_RECREATE_TRANSACTION_CHANGED")
	}
	if old.State == "attempt" && next.State == "mapped" {
		return nil
	}
	if old.State == "mapped" && next.State == "ready" {
		p := next.Next
		p.Created = 0
		if p == old.Next {
			return nil
		}
	}
	if old.State == "mapped" && next.State == "mapped" {
		p := next.Next
		p.Planned = old.Next.Planned
		if p == old.Next && next.Next.Planned >= old.Next.Planned {
			return nil
		}
	}
	return fmt.Errorf("USB_HOST_RECREATE_PHASE_INVALID")
}

// A re-creation journal must be unambiguous before any native mutation, not
// merely when the final ownership transition is committed.
func decodeRecreateJournal(b []byte) (journal, error) {
	var shape struct{ Version int }
	_ = json.Unmarshal(b, &shape)
	fields := []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token"}
	if shape.Version == 2 {
		fields = append(fields, "AddressMode", "PersistentSHA256")
	}
	if len(b) > 2048 || !exactJSONFields(b, fields) {
		return journal{}, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_INVALID")
	}
	p, e := decodeJournal(b)
	if e != nil {
		return journal{}, fmt.Errorf("USB_HOST_RECREATE_JOURNAL_INVALID")
	}
	return p, nil
}

// ready permits the one atomic old->new journal transition. It never permits
// fixed-name adoption after an unknown call or replacing somebody else's file.
func recreateJournalPosition(t recreateTransaction, b []byte) (string, error) {
	p, e := decodeRecreateJournal(b)
	if e != nil {
		return "", fmt.Errorf("USB_HOST_RECREATE_JOURNAL_INVALID")
	}
	if journalDigest(b) == t.OldSHA256 {
		if p.Created <= 0 || p.LUID != t.OriginalLUID {
			return "", fmt.Errorf("USB_HOST_RECREATE_OLD_OWNERSHIP_UNPROVEN")
		}
		return "old", nil
	}
	next, _ := json.Marshal(t.Next)
	if t.State == "ready" && p == t.Next && bytes.Equal(b, next) {
		return "new", nil
	}
	return "", fmt.Errorf("USB_HOST_RECREATE_JOURNAL_CHANGED")
}

func recreateUnknownRecoveryGate(t recreateTransaction, ticks uint64) error {
	if ticks == 0 || ticks >= t.Ticks {
		return fmt.Errorf("USB_HOST_RECREATE_REBOOT_UNPROVEN")
	}
	return nil
}

func rebindClosing(p journal, index uint32, luid uint64, addresses []recoveryAddress) (journal, string, error) {
	if p.Created <= 0 || p.LUID == 0 || luid != p.LUID {
		return journal{}, "unproven", fmt.Errorf("USB_HOST_CLOSE_OWNERSHIP_UNPROVEN")
	}
	return rebindRecovery(p, index, luid, addresses)
}

// A missing interface has no current index. Zero disables index matching so
// a historical index reused by another interface cannot fence LUID-only absence.
func recoveryAddressMatches(index uint32, luid uint64, rowIndex uint32, rowLUID uint64) bool {
	return rowLUID == luid || (index != 0 && rowIndex == index)
}

// Only the uninterrupted live Start stack supplies this returned-handle
// observation. A mapped receipt alone never authorizes opening/adopting a
// device, creating an address or replaying DAD after a crash.
type recreatedDADHandle struct {
	FactoryHeld bool
	GUID        string
	Index       uint32
	LUID        uint64
	Instance    string
}

// The old completed journal intentionally remains unchanged until ready. Bind
// both generations rather than comparing the new token to the old journal.
func validateRecreatedDADOwnership(t recreateTransaction, old []byte, p journal, handle recreatedDADHandle) error {
	raw, e := json.Marshal(t)
	if e != nil {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_PHASE_UNPROVEN")
	}
	if _, e = decodeRecreateTransaction(raw); e != nil {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_PHASE_UNPROVEN")
	}
	if t.State != "mapped" || t.Next != p || p.Created != 0 || p.Index == 0 || p.LUID == 0 || p.Token != t.Token {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_PHASE_UNPROVEN")
	}
	position, e := recreateJournalPosition(t, old)
	if e != nil || position != "old" {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_JOURNAL_CHANGED")
	}
	if !handle.FactoryHeld || handle.GUID != p.GUID || handle.Index != p.Index || handle.LUID != p.LUID || handle.Instance != t.Instance {
		return fmt.Errorf("USB_HOST_OWNED_DAD_RECREATE_HANDLE_CHANGED")
	}
	return nil
}

// Index must never participate in unknown-outcome address absence: it may now
// belong to another interface. Both saved lifecycle LUIDs must remain empty.
func recreateAbsenceLUIDs(t recreateTransaction) []uint64 {
	out := []uint64{t.OriginalLUID}
	if t.Next.LUID != 0 && t.Next.LUID != t.OriginalLUID {
		out = append(out, t.Next.LUID)
	}
	return out
}

// This is only an additional absence gate, never authorization to clear a
// transaction. Native node/MIB absence, protected bytes and the reboot gate
// remain mandatory at the call sites.
func verifyRecreateAbsentAddressReads(t recreateTransaction, read func(uint64) (int, error)) error {
	if read == nil {
		return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_NOT_ABSENT")
	}
	for _, luid := range recreateAbsenceLUIDs(t) {
		count, e := read(luid)
		if luid == 0 || e != nil || count != 0 {
			return fmt.Errorf("USB_HOST_RECREATE_ADDRESS_NOT_ABSENT")
		}
	}
	return nil
}
