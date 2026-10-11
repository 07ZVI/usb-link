//go:build windows && amd64

package ipadncm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// These owner contract tests use memory only. They must not call a service,
// USB operation or file reader; Windows fixture compilation is not execution.
func TestUnpairedPendingBlocksOtherOwnersAndUpgradeWithoutNativeWork(t *testing.T) {
	unpairedExperiment.Lock()
	old := unpairedExperiment.model
	unpairedExperiment.model = unpairedExperimentModel{status: UnpairedExperimentStatus{State: "PREPARE_PENDING", Pending: true}}
	unpairedExperiment.Unlock()
	defer func() { unpairedExperiment.Lock(); unpairedExperiment.model = old; unpairedExperiment.Unlock() }()
	if RequestNetworkOnly(false) == nil || RequestIPadCandidateStage(0) == nil || HoldIPadModeDiagnostics() == nil || StartAMDSModeDiagnostic(context.Background(), "test", "running") == nil || RequestIPadSoftwareReconnect(context.Background()) == nil || RequestIPadSoftwareReconnectSetting(context.Background(), false) == nil {
		t.Fatal("another writer admitted during unpaired owner")
	}
	if release, e := reserveIPadUpgrade(); e == nil {
		if release != nil {
			release()
		}
		t.Fatal("upgrade canceled or superseded experiment instead of refusing")
	}
	s, e := ObserveUnpairedExperimentMetadata()
	if e != nil || !s.Pending || s.Attempts != 0 || s.SerialSHA256 != "" {
		t.Fatal("unbound STATE performed metadata lookup or granted a scope")
	}
}
func TestUnpairedFinishedAndRejectedStateAreNotDeviceAuthorization(t *testing.T) {
	unpairedExperiment.Lock()
	old := unpairedExperiment.model
	oldBorrowed := unpairedExperiment.borrowed
	unpairedExperiment.model = unpairedExperimentModel{status: UnpairedExperimentStatus{State: "FINISHED", RestoreVerified: true}}
	unpairedExperiment.borrowed = false
	unpairedExperiment.Unlock()
	defer func() {
		unpairedExperiment.Lock()
		unpairedExperiment.model = old
		unpairedExperiment.borrowed = oldBorrowed
		unpairedExperiment.Unlock()
	}()
	if UnpairedExperimentBusy() || UnpairedExperimentCanConnect() {
		t.Fatal("finished diagnostic fabricated permission or blocked upgrade")
	}
	if e := FinishUnpairedExperimentOwner(context.Background(), "unused", "unused", false); e != nil {
		t.Fatal("second exit invented a restoration obligation")
	}
	unpairedExperiment.Lock()
	unpairedExperiment.model.status = UnpairedExperimentStatus{State: "REJECTED"}
	unpairedExperiment.Unlock()
	if UnpairedExperimentBusy() || RecordUnpairedExperimentReplied() == nil {
		t.Fatal("rejection became owner or response authority")
	}
}
func TestUnpairedMemoryOnlyActiveCannotAdmitUnknownNativeDevice(t *testing.T) {
	unpairedExperiment.Lock()
	old := unpairedExperiment.model
	oldBorrowed := unpairedExperiment.borrowed
	unpairedExperiment.model = unpairedExperimentModel{status: UnpairedExperimentStatus{State: "BOUND", Attempts: 1}, expires: time.Now().Add(time.Minute), root: "not-a-device"}
	unpairedExperiment.borrowed = true
	unpairedExperiment.Unlock()
	defer func() {
		unpairedExperiment.Lock()
		unpairedExperiment.model = old
		unpairedExperiment.borrowed = oldBorrowed
		unpairedExperiment.Unlock()
	}()
	allowed, problem := NetworkOnlyDriverAdmission(Snapshot{})
	if allowed || problem != "UNPAIRED_EXPERIMENT_NATIVE_SCOPE_UNPROVEN" {
		t.Fatal("cached active experiment bypassed fresh native scope", allowed, problem)
	}
}

func TestUnpairedFinalAttemptKeepsMetadataCauseAndRedactsLegacyProof(t *testing.T) {
	unpairedExperiment.Lock()
	old := unpairedExperiment.model
	borrowed := unpairedExperiment.borrowed
	unpairedExperiment.model = preparedUnpairedModel(time.Now())
	unpairedExperiment.borrowed = true
	const cause = "PAIR_METADATA_CHECK: UNPAIRED_ORIGINAL_STORE_UNVERIFIED"
	unpairedExperiment.model.stop(cause)
	unpairedExperiment.Unlock()
	oldFeatures := unpairedFeatureLease.Load()
	defer func() {
		unpairedExperiment.Lock()
		unpairedExperiment.model = old
		unpairedExperiment.borrowed = borrowed
		unpairedExperiment.Unlock()
		unpairedFeatureLease.Store(oldFeatures)
	}()
	a := &ConnectionAuthorization{ConsentStatus: "USB_ALLOWED", Once: true, USBInfoMatched: true, Proof: PairedIdentity{Error: "private-pair-content", identity: "private-pair-identity", key: "private-pair-key"}, InitialUSB: &Snapshot{Devices: []Device{{USBSerialReadStatus: "USB_STRING_VERIFIED", Errors: []string{"C:\\private\\node-or-pair-path"}, usbSerial: "private-descriptor-value"}}}}
	CompleteUnpairedExperimentAttempt("UNPAIRED_EXPERIMENT_SCOPE_UNPROVEN", "unpaired metadata: UNPAIRED_ORIGINAL_STORE_UNVERIFIED", a)
	s := UnpairedExperimentSnapshot()
	if s.FirstFailure != cause || s.Problem != cause || s.LastAttempt == nil || s.LastAttempt.MetadataError != "UNPAIRED_ORIGINAL_STORE_UNVERIFIED" || s.LastAttempt.ConsentStatus != "USB_ALLOWED" {
		t.Fatal("first metadata failure lost", s)
	}
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"private-pair", "private-descriptor", "private\\node"} {
		if strings.Contains(string(b), v) {
			t.Fatal("pairing or raw USB/path private detail exported")
		}
	}
}
