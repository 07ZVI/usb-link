//go:build windows && amd64

package usbhost

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/platform/windows/netconfig"
)

func readHostDiagnosticJournal(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 2049))
}

// StartupOwnershipDiagnostic is a fresh, read-only observation. It does not
// change live state, checkpoint a journal, authorize recovery, or delete an
// adapter. Journal tokens, instance strings and arbitrary errors stay private.
type StartupOwnershipDiagnostic struct {
	PersistentFactoryPresent   bool                                `json:"persistent_factory_present"`
	PersistentFactoryValid     bool                                `json:"persistent_factory_valid"`
	PersistentFactoryPhase     string                              `json:"persistent_factory_phase,omitempty"`
	PersistentFactoryProblem   string                              `json:"persistent_factory_problem,omitempty"`
	ObservationOnly            bool                                `json:"observation_only"`
	JournalPresent             *bool                               `json:"journal_present"`
	JournalValid               bool                                `json:"journal_valid"`
	JournalStable              bool                                `json:"journal_stable"`
	JournalIndex               uint32                              `json:"journal_index"`
	JournalLUID                uint64                              `json:"journal_luid"`
	JournalCreated             int64                               `json:"journal_created_stamp"`
	JournalPlanned             int64                               `json:"journal_planned_stamp"`
	NativePresent              bool                                `json:"native_present"`
	NativeIdentityValid        bool                                `json:"native_identity_valid"`
	NativeIndex                uint32                              `json:"native_index"`
	NativeLUID                 uint64                              `json:"native_luid"`
	MappingChanged             bool                                `json:"mapping_changed"`
	IPv4Count                  int                                 `json:"ipv4_count"`
	AddressState               string                              `json:"address_state"`
	CurrentCreated             int64                               `json:"current_created_stamp,omitempty"`
	Problem                    string                              `json:"problem,omitempty"`
	DriverObservation          *netconfig.HostIdentityDiagnostic   `json:"driver_observation,omitempty"`
	RemovalIntentPresent       bool                                `json:"removal_intent_present"`
	RemovalIntentState         string                              `json:"removal_intent_state,omitempty"`
	RemovalJournalMatches      bool                                `json:"removal_journal_matches"`
	RemovalCounterResetProven  bool                                `json:"removal_counter_reset_proven"`
	RemovalProblem             string                              `json:"removal_problem,omitempty"`
	RecreateTransactionPresent bool                                `json:"recreate_transaction_present"`
	RecreateTransactionValid   bool                                `json:"recreate_transaction_valid"`
	RecreatePhase              string                              `json:"recreate_phase,omitempty"`
	RecreateJournalMatches     bool                                `json:"recreate_journal_matches"`
	RecreateProblem            string                              `json:"recreate_problem,omitempty"`
	RecreateJournalProtection  RecreateJournalProtectionDiagnostic `json:"recreate_journal_protection"`
}

// InspectStartupOwnership only accepts the application's existing recovery
// directory from a local caller; RPCs must not expose directory selection.
func InspectStartupOwnership(dir string) StartupOwnershipDiagnostic {
	d := StartupOwnershipDiagnostic{ObservationOnly: true, AddressState: "unobserved"}
	factory, found, fe := readPersistentFactory(dir)
	d.PersistentFactoryPresent = found
	if fe != nil {
		d.PersistentFactoryProblem = "USB_HOST_FACTORY_RECORD_UNPROVEN"
	} else if found {
		d.PersistentFactoryValid = true
		d.PersistentFactoryPhase = factory.State
	}

	d.RecreateJournalProtection = inspectRecreateJournalProtection(dir)
	path := filepath.Join(dir, "usb-host-address.json")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		b := false
		d.JournalPresent = &b
	} else if e != nil {
		d.Problem = "USB_HOST_JOURNAL_UNREADABLE"
	} else {
		b := true
		d.JournalPresent = &b
		if !info.Mode().IsRegular() || info.Size() > 2048 {
			d.Problem = "USB_HOST_JOURNAL_INVALID"
		}
	}
	var p journal
	var original []byte
	if d.JournalPresent != nil && *d.JournalPresent && d.Problem == "" {
		original, e = readHostDiagnosticJournal(path)
		if e != nil {
			d.Problem = "USB_HOST_JOURNAL_UNREADABLE"
		} else {
			p, e = decodeJournal(original)
			if e != nil {
				d.Problem = "USB_HOST_JOURNAL_INVALID"
			} else {
				d.JournalValid = true
				d.JournalIndex = p.Index
				d.JournalLUID = p.LUID
				d.JournalCreated = p.Created
				d.JournalPlanned = p.Planned
			}
		}
	}
	// Fixed private sidecar observation is available even after the interface
	// disappears. These bounded fields never authorize recovery.
	intent, found, ie := readRemovalIntentFile(dir)
	transaction, tfound, te := readRecreateTransactionFile(dir)
	d.RecreateTransactionPresent = tfound
	if te != nil {
		d.RecreateProblem = "USB_HOST_RECREATE_TRANSACTION_UNPROVEN"
	} else if tfound {
		d.RecreateTransactionValid = true
		d.RecreatePhase = transaction.State
		_, pe := recreateJournalPosition(transaction, original)
		d.RecreateJournalMatches = pe == nil
		if pe != nil {
			d.RecreateProblem = pe.Error()
		} else if transaction.State == "attempt" || transaction.State == "mapped" {
			if ge := recreateUnknownRecoveryGate(transaction, systemTicks()); ge != nil {
				d.RecreateProblem = ge.Error()
			}
		}
		if found {
			d.RecreateProblem = "USB_HOST_RECREATE_CONFLICTS_WITH_REMOVAL"
		}
	}
	d.RemovalIntentPresent = found
	if ie != nil {
		d.RemovalProblem = "USB_HOST_REMOVAL_INTENT_UNPROVEN"
	} else if found {
		d.RemovalIntentState = intent.State
		d.RemovalJournalMatches = d.JournalValid && journalDigest(original) == intent.JournalSHA256
		ticks := systemTicks()
		d.RemovalCounterResetProven = ticks > 0 && ticks < intent.Ticks
		if ge := removalRecoveryGate(intent, original, d.JournalPresent != nil && *d.JournalPresent, ticks); ge != nil {
			d.RemovalProblem = ge.Error()
		}
	}
	r, present, e := findHost()
	d.NativePresent = present
	if e != nil {
		if d.Problem == "" {
			d.Problem = "USB_HOST_NATIVE_IDENTITY_UNPROVEN"
		}
		return d
	}
	if !present {
		return d
	}
	d.NativeIdentityValid = true
	d.NativeIndex = r.InterfaceIndex
	d.NativeLUID = r.InterfaceLuid
	identity := netconfig.InspectSharedHostIdentity(r.InterfaceIndex)
	d.DriverObservation = &identity
	if !d.JournalValid {
		return d
	}
	d.MappingChanged = p.Index != r.InterfaceIndex || p.LUID != r.InterfaceLuid
	addresses, e := recoveryAddresses(r.InterfaceIndex, r.InterfaceLuid)
	if e != nil {
		if d.Problem == "" {
			d.Problem = "USB_HOST_NATIVE_ADDRESS_QUERY_FAILED"
		}
		return d
	}
	d.IPv4Count = len(addresses)
	if len(addresses) == 1 {
		d.CurrentCreated = addresses[0].Created
	}
	_, d.AddressState, e = rebindRecovery(p, r.InterfaceIndex, r.InterfaceLuid, addresses)
	if e != nil && d.Problem == "" {
		d.Problem = e.Error()
	} // Pure helper emits fixed codes only.
	readback, e := readHostDiagnosticJournal(path)
	d.JournalStable = e == nil && bytes.Equal(original, readback)
	if !d.JournalStable {
		d.Problem = "USB_HOST_JOURNAL_CHANGED_DURING_OBSERVATION"
	}
	return d
}
