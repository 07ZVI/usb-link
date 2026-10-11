package usbhost

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
)

// The original Store identity never follows a newly returned adapter. Source
// is the last complete address journal, while Mapped is only a known DLL return.
// Neither an attempt nor a raw fixed GUID can become an ownership proof.
type persistentFactory struct {
	Version        int
	OriginalSHA256 string
	OriginalScope  interfaceconfig.Scope
	Original       interfaceconfig.PersistentOriginalSnapshot
	JournalSHA256  string
	Source         journal
	Instance       string
	State          string
	Attempt        string
	Ticks          uint64
	MappedIndex    uint32
	MappedLUID     uint64
	Next           journal
}

var factoryNetworkGUID = regexp.MustCompile(`^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$`)
var factoryFields = []string{"Version", "OriginalSHA256", "OriginalScope", "Original", "JournalSHA256", "Source", "Instance", "State", "Attempt", "Ticks", "MappedIndex", "MappedLUID", "Next"}

func factoryHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func validFactoryJournal(p journal) bool {
	b, e := json.Marshal(p)
	if e != nil {
		return false
	}
	q, e := decodeJournal(b)
	return e == nil && q == p && p.Version == 2
}
func decodePersistentFactory(b []byte) (persistentFactory, error) {
	var v persistentFactory
	if len(b) > 4096 || !exactJSONFields(b, factoryFields) || json.Unmarshal(b, &v) != nil || v.Version != 1 || !factoryHex(v.OriginalSHA256, 64) || !factoryHex(v.JournalSHA256, 64) || !validFactoryJournal(v.Source) || v.Source.PersistentSHA256 != v.OriginalSHA256 || v.OriginalScope.Role != "host" || v.OriginalScope.GUID != v.Source.GUID || v.OriginalScope.Index == 0 || v.OriginalScope.LUID == 0 || len(v.Instance) == 0 || len(v.Instance) > 512 || strings.ContainsAny(v.Instance, "*?\x00") {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	// Nested records use the same strict unique-field journal contract. Unknown
	// fields, duplicates, and incomplete original scopes are rejected before DLL.
	var members map[string]json.RawMessage
	if json.Unmarshal(b, &members) != nil || !exactJSONFields(members["OriginalScope"], []string{"role", "guid", "index", "luid"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	if !exactJSONFields(members["Source"], []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token", "AddressMode", "PersistentSHA256"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	if v.State == "proved" && !exactJSONFields(members["Next"], []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token", "AddressMode", "PersistentSHA256"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	if v.State != "proved" && !exactJSONFields(members["Next"], []string{"Version", "GUID", "Index", "LUID", "Planned", "Created", "Token"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	if !exactJSONFields(members["Original"], []string{"ImmutableScope", "SHA256", "OriginalMTU", "DesiredMTU", "AddressAbsent", "Address", "Prefix", "NetworkGUID", "OriginalCategory", "AppliedValidLifetime", "AppliedPreferredLifetime"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	var originalMembers map[string]json.RawMessage
	if json.Unmarshal(members["Original"], &originalMembers) != nil || !exactJSONFields(originalMembers["ImmutableScope"], []string{"role", "guid", "index", "luid"}) {
		return persistentFactory{}, errors.New("USB_HOST_FACTORY_RECORD_INVALID")
	}
	if e := validatePersistentFactory(v); e != nil {
		return persistentFactory{}, e
	}
	return v, nil
}
func validatePersistentFactory(v persistentFactory) error {
	fail := errors.New("USB_HOST_FACTORY_PHASE_INVALID")
	if v.Original.ImmutableScope != v.OriginalScope || v.Original.SHA256 != v.OriginalSHA256 || v.Original.OriginalMTU < 576 || v.Original.OriginalMTU > 65535 || v.Original.DesiredMTU != 1500 || !v.Original.AddressAbsent || v.Original.Address != "10.6.9.1" || v.Original.Prefix != 32 || v.Original.OriginalCategory > 1 || !factoryNetworkGUID.MatchString(v.Original.NetworkGUID) || len(v.Original.AppliedValidLifetime) == 0 || len(v.Original.AppliedValidLifetime) > 128 || len(v.Original.AppliedPreferredLifetime) == 0 || len(v.Original.AppliedPreferredLifetime) > 128 {
		return fail
	}
	switch v.State {
	case "ready", "closed", "restoring", "stopped":
		if v.Attempt != "" || v.Ticks != 0 || v.MappedIndex != 0 || v.MappedLUID != 0 || v.Next != (journal{}) {
			return fail
		}
	case "attempt", "restore_attempt", "removing", "removed", "removal_unknown", "removal_restart":
		if !factoryHex(v.Attempt, 32) || v.Ticks == 0 || v.MappedIndex != 0 || v.MappedLUID != 0 || v.Next != (journal{}) {
			return fail
		}
	case "mapped", "restore_mapped", "restore_stopped", "restore_removing", "restore_removed", "restore_removal_unknown", "restore_removal_restart":
		if !factoryHex(v.Attempt, 32) || v.Ticks == 0 || v.MappedIndex == 0 || v.MappedLUID == 0 || v.Next != (journal{}) {
			return fail
		}
	case "proved":
		if !validFactoryJournal(v.Next) || v.Next.PersistentSHA256 != v.OriginalSHA256 || v.Next.Token != v.Source.Token || v.Next.GUID != v.Source.GUID || v.MappedIndex != v.Next.Index || v.MappedLUID != v.Next.LUID {
			return fail
		}
		if (v.Attempt == "") != (v.Ticks == 0) || v.Attempt != "" && !factoryHex(v.Attempt, 32) {
			return fail
		}
	default:
		return fail
	}
	return nil
}
func factorySameOriginal(a, b persistentFactory) bool {
	return a.Version == b.Version && a.OriginalScope == b.OriginalScope && a.OriginalSHA256 == b.OriginalSHA256 && a.Original == b.Original && a.Instance == b.Instance
}
func validatePersistentFactoryTransition(a, b persistentFactory) error {
	fail := errors.New("USB_HOST_FACTORY_TRANSITION_INVALID")
	if !factorySameOriginal(a, b) || validatePersistentFactory(a) != nil || validatePersistentFactory(b) != nil {
		return fail
	}
	if a == b {
		return nil
	}
	if a.State == "proved" && b.State == "ready" {
		if b.Source != a.Next || b.JournalSHA256 != journalDigestJSON(a.Next) {
			return fail
		}
		return nil
	}
	if a.Source != b.Source || a.JournalSHA256 != b.JournalSHA256 {
		return fail
	}
	switch a.State + ">" + b.State {
	case "ready>restore_attempt", "closed>restore_attempt", "restoring>restore_attempt":
		return nil
	case "restore_attempt>restore_mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	case "restore_attempt>closed", "restore_mapped>closed":
		return nil // caller requires original still present and reboot+full absence
	case "restore_mapped>restore_mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "restore_mapped>restore_stopped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks && a.MappedIndex == b.MappedIndex && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "restore_stopped>restore_removing":
		if a.MappedIndex == b.MappedIndex && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "restore_removing>restore_removed", "restore_removing>restore_removal_unknown", "restore_removing>restore_removal_restart", "restore_removal_unknown>restore_removed", "restore_removal_restart>restore_removed":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks && a.MappedIndex == b.MappedIndex && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "restoring>stopped":
		return nil
	case "ready>closed", "ready>restoring", "closed>restoring":
		return nil
	case "closed>attempt", "stopped>removing":
		return nil
	case "attempt>closed", "mapped>closed":
		return nil // caller requires no-call or reboot+full absence
	case "removing>removed", "removing>removal_unknown", "removing>removal_restart", "removal_unknown>removed", "removal_restart>removed":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	case "mapped>mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "attempt>mapped":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks {
			return nil
		}
	case "mapped>proved":
		if a.Attempt == b.Attempt && a.Ticks == b.Ticks && a.MappedIndex == b.MappedIndex && a.MappedLUID == b.MappedLUID {
			return nil
		}
	case "ready>proved":
		if b.Next.LUID == a.Source.LUID && b.Attempt == "" {
			return nil
		}
	}
	return fail
}
func journalDigestJSON(p journal) string { b, _ := json.Marshal(p); return journalDigest(b) }

// A durable successful proof permits exactly old bytes or its exact next
// bytes. Unknown attempts never gain a next-journal adoption path.
func persistentFactoryJournalPosition(v persistentFactory, b []byte) (bool, error) {
	p, e := decodeJournal(b)
	if e != nil {
		return false, e
	}
	if p == v.Source && journalDigest(b) == v.JournalSHA256 {
		return false, nil
	}
	if v.State == "proved" && p == v.Next && journalDigest(b) == journalDigestJSON(v.Next) {
		return true, nil
	}
	return false, errors.New("USB_HOST_FACTORY_JOURNAL_CHANGED")
}

func persistentFactoryUnknownAbsent(v persistentFactory, ticks uint64, absent bool, oldAddresses, newAddresses int) error {
	if (v.State != "attempt" && v.State != "mapped" && v.State != "restore_attempt" && v.State != "restore_mapped" && v.State != "removing" && v.State != "removal_unknown" && v.State != "removal_restart" && v.State != "restore_removing" && v.State != "restore_removal_unknown" && v.State != "restore_removal_restart") || ticks == 0 || v.Ticks == 0 || ticks >= v.Ticks {
		return errors.New("USB_HOST_FACTORY_UNKNOWN_CALL_RESTART_REQUIRED")
	}
	if !absent || oldAddresses != 0 || newAddresses != 0 {
		return errors.New("USB_HOST_FACTORY_UNKNOWN_CALL_ABSENCE_UNPROVEN")
	}
	return nil
}

// Removal completion may resume after the first file was already deleted.
// Every other phase requires the original complete journal to stay present.
func persistentFactoryFinalJournalGate(v persistentFactory, b []byte, present bool) error {
	if (v.State != "removed" && v.State != "restore_removed") || validatePersistentFactory(v) != nil {
		return errors.New("USB_HOST_FACTORY_FINAL_PHASE_INVALID")
	}
	if !present {
		return nil
	}
	_, e := persistentFactoryJournalPosition(v, b)
	return e
}

// Restore-only mappings can never supply a network journal or publish Ready.
// The immutable Source continues to identify the pre-uninstall obligation.
func factoryRestoreMappedPhase(state string) bool {
	switch state {
	case "restore_mapped", "restore_stopped", "restore_removing", "restore_removed", "restore_removal_unknown", "restore_removal_restart":
		return true
	}
	return false
}
func factoryRemovalLUID(v persistentFactory) uint64 {
	if factoryRestoreMappedPhase(v.State) {
		return v.MappedLUID
	}
	return v.Source.LUID
}
func factoryRemovalPhase(v persistentFactory, phase string) string {
	if factoryRestoreMappedPhase(v.State) {
		return "restore_" + phase
	}
	return phase
}
