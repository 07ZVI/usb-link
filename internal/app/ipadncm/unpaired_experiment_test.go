package ipadncm

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func preparedUnpairedModel(now time.Time) unpairedExperimentModel {
	return unpairedExperimentModel{status: UnpairedExperimentStatus{State: "PREPARED"}, expires: now.Add(10 * time.Minute)}
}
func unpairedTestMetadata() UnpairedPairMetadata {
	return UnpairedPairMetadata{true, true, "201e", strings.Repeat("a", 64)}
}
func TestUnpairedDefaultOffOneAttemptAndLease(t *testing.T) {
	now := time.Now()
	var off unpairedExperimentModel
	if off.live(now) || off.bind(now, "root", unpairedTestMetadata().USBSerialSHA256, unpairedTestMetadata()) == nil {
		t.Fatal("default OFF acquired permission")
	}
	m := preparedUnpairedModel(now)
	v := unpairedTestMetadata()
	if m.bind(now, "root", v.USBSerialSHA256, v) != nil || m.status.Attempts != 1 {
		t.Fatal("fresh scope rejected")
	}
	if m.bind(now, "other", v.USBSerialSHA256, v) == nil {
		t.Fatal("second attempt or scope replacement accepted")
	}
	if m.live(now.Add(10 * time.Minute)) {
		t.Fatal("deadline boundary still live")
	}
	m.stop("LEASE_EXPIRED")
	if m.live(now) {
		t.Fatal("pending restoration permitted USB")
	}
	m.restored(errors.New("readback failure"))
	if !m.status.Blocked || m.status.RestoreVerified || m.live(now) {
		t.Fatal("restoration fault lost obligation")
	}
	m.restored(nil)
	if m.status.State != "FINISHED" || !m.status.RestoreVerified || m.live(now) {
		t.Fatal("finished experiment rearmed itself")
	}
}
func TestUnpairedMetadataUnknownWrongDeviceAndSuffixNotAuthority(t *testing.T) {
	now := time.Now()
	v := unpairedTestMetadata()
	for _, tc := range []struct {
		name   string
		change func(*UnpairedPairMetadata)
	}{
		{"original_reappeared", func(v *UnpairedPairMetadata) { v.OriginalAbsent = false }},
		{"backup_missing", func(v *UnpairedPairMetadata) { v.BackupPresent = false }},
		{"wrong_device_same_suffix", func(v *UnpairedPairMetadata) { v.USBSerialSHA256 = strings.Repeat("b", 64) }},
		{"unknown_digest", func(v *UnpairedPairMetadata) { v.USBSerialSHA256 = "" }},
		{"unbounded_suffix", func(v *UnpairedPairMetadata) { v.USBSerialSuffix = "private-instance-path" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := v
			tc.change(&copy)
			m := preparedUnpairedModel(now)
			if m.bind(now, "root", v.USBSerialSHA256, copy) == nil || m.status.Attempts != 0 {
				t.Fatal("bad metadata captured scope")
			}
		})
	}
	for _, state := range []UnpairedExperimentStatus{{State: "PREPARED", Pending: true}, {State: "PREPARED", Busy: true}, {State: "PREPARED", Blocked: true}, {State: "BOUND", Attempts: 1}} {
		m := preparedUnpairedModel(now)
		m.status = state
		if m.bind(now, "root", v.USBSerialSHA256, v) == nil {
			t.Fatal("inactive owner captured scope")
		}
	}
}
func TestUnpairedServiceReceiptAndNativePolicyNegativeMatrix(t *testing.T) {
	good := []uint32{4, 2, 4, 2, 1, 3}
	if !unpairedExpectedServicePolicy(true, good[0], good[1], good[2], good[3], good[4], good[5]) {
		t.Fatal("owned stopped/manual policy rejected")
	}
	for index := range good {
		p := append([]uint32(nil), good...)
		p[index] = 99
		if unpairedExpectedServicePolicy(true, p[0], p[1], p[2], p[3], p[4], p[5]) {
			t.Fatalf("invalid field %d admitted", index)
		}
	}
	if unpairedExpectedServicePolicy(false, 4, 2, 4, 2, 1, 3) || unpairedExpectedServicePolicy(true, 4, 2, 4, 2, 4, 2) || unpairedExpectedServicePolicy(true, 4, 2, 1, 2, 1, 3) {
		t.Fatal("missing service, unstopped service or different original admitted")
	}
	if !unpairedExpectedServicePolicy(true, 1, 3, 1, 3, 1, 3) {
		t.Fatal("original stable stopped/manual rejected")
	}
}
func TestUnpairedRestoreCannotRunBeforeSessionCleanup(t *testing.T) {
	writes := 0
	recover := func() error { writes++; return errors.New("native readback failure") }
	if unpairedRestoreOwned(false, true, recover) == nil || writes != 0 {
		t.Fatal("restored before address/session journal cleanup")
	}
	if unpairedRestoreOwned(true, false, recover) != nil || writes != 0 {
		t.Fatal("touched non-owned state")
	}
	if unpairedRestoreOwned(true, true, recover) == nil || writes != 1 {
		t.Fatal("owned restoration failure swallowed")
	}
	if unpairedRestoreOwned(true, true, func() error { writes++; return nil }) != nil || writes != 2 {
		t.Fatal("exact owned retry failed")
	}
	m := preparedUnpairedModel(time.Now())
	m.reject(errors.New("official driver absent"))
	if m.status.Blocked || m.status.State != "REJECTED" || m.status.RestoreVerified {
		t.Fatal("preflight rejection invented a recovery obligation")
	}
}
func TestUnpairedDiagnosticBoundariesAndBounds(t *testing.T) {
	now := time.Now()
	m := preparedUnpairedModel(now)
	v := unpairedTestMetadata()
	_ = m.bind(now, "private-root", v.USBSerialSHA256, v)
	for i := 0; i < 100; i++ {
		m.event(now.Add(time.Second), "dhcp_request")
	}
	if m.status.DHCPRequestsBeforeReply != 100 || len(m.status.Events) != 1 {
		t.Fatal("DHCP repeats unbounded or lost")
	}
	m.status.RepliedUTC = now.Add(2 * time.Second).UTC().Format(time.RFC3339Nano)
	m.event(now.Add(3*time.Second), "dhcp_request")
	m.event(now.Add(3*time.Second), "ipv4_neighbor_verified_not_arp_capture")
	for i := 0; i < 100; i++ {
		m.metadata(now, "explicit_result", v)
	}
	if m.status.DHCPRequestsAfterReply != 1 || len(m.status.Events) != 3 || len(m.status.Metadata) != 8 || m.status.ARPCaptureSupported || m.status.GeneralUDPCaptureSupported {
		t.Fatal("invented packet capture or unbounded diagnostics")
	}
	b, _ := json.Marshal(m.status)
	if strings.Contains(string(b), "private-root") || strings.Contains(string(b), "after_user_replied") || !strings.Contains(string(b), "after_operator_recorded_reply") {
		t.Fatal("private scope or false click-time exported")
	}
	m.stop("done")
	m.event(now.Add(4*time.Second), "dhcp_request")
	if m.status.DHCPRequestsAfterReply != 1 {
		t.Fatal("post-lease packet counted")
	}
}
func TestUnpairedTemporaryFeaturesDoNotRewriteCandidateStage(t *testing.T) {
	candidateFeatureState.Lock()
	old := candidateFeatureState.stage
	candidateFeatureState.stage = 0
	candidateFeatureState.Unlock()
	oldLease := unpairedFeatureLease.Swap(false)
	defer func() {
		candidateFeatureState.Lock()
		candidateFeatureState.stage = old
		candidateFeatureState.Unlock()
		unpairedFeatureLease.Store(oldLease)
	}()
	if IPadCandidateFeatures() != (CandidateFeatures{}) {
		t.Fatal("default experiment features enabled")
	}
	unpairedFeatureLease.Store(true)
	if IPadCandidateFeatures() != (CandidateFeatures{true, true, true, true}) {
		t.Fatal("bounded experiment features absent")
	}
	candidateFeatureState.Lock()
	stage := candidateFeatureState.stage
	candidateFeatureState.Unlock()
	if stage != 0 {
		t.Fatal("experiment fabricated accepted stage")
	}
	unpairedFeatureLease.Store(false)
	if IPadCandidateFeatures() != (CandidateFeatures{}) {
		t.Fatal("lease teardown retained features")
	}
}

func TestUnpairedFirstFailureSurvivesCompletionAndRestoration(t *testing.T) {
	m := preparedUnpairedModel(time.Now())
	const cause = "PAIR_METADATA_CHECK: UNPAIRED_ORIGINAL_STORE_UNVERIFIED"
	m.stop(cause)
	m.stop("ONE_ATTEMPT_COMPLETE")
	m.restored(nil)
	if m.status.FirstFailure != cause || m.status.Problem != cause || m.status.CompletionReason != "ONE_ATTEMPT_COMPLETE" || !m.status.RestoreVerified {
		t.Fatal("metadata cause was overwritten by normal completion", m.status)
	}
	m.stop("SECONDARY_FAILURE")
	m.restored(errors.New("native restore failed"))
	if m.status.FirstFailure != cause || m.status.Problem != cause || m.status.RestoreProblem != "native restore failed" || !m.status.Blocked {
		t.Fatal("restore failure overwrote first cause or hid restoration fault")
	}
	m.restored(nil)
	if m.status.RestoreProblem != "" || m.status.FirstFailure != cause {
		t.Fatal("restored retry erased history or retained unresolved restore error")
	}
}
func TestUnpairedStartupHoldDefaultAndOnlyPreparedOneAttemptRelease(t *testing.T) {
	now := time.Now()
	var off unpairedExperimentModel
	if unpairedDiagnosticShouldHold(false, off, now) {
		t.Fatal("default startup hold enabled")
	}
	if !unpairedDiagnosticShouldHold(true, off, now) {
		t.Fatal("ordinary iPad path runs before diagnostic")
	}
	m := preparedUnpairedModel(now)
	if unpairedDiagnosticShouldHold(true, m, now) {
		t.Fatal("explicit prepared experiment held")
	}
	v := unpairedTestMetadata()
	_ = m.bind(now, "root", v.USBSerialSHA256, v)
	if !unpairedDiagnosticShouldHold(true, m, now) {
		t.Fatal("startup hold admitted a second bound attempt")
	}
	m = preparedUnpairedModel(now)
	if !unpairedDiagnosticShouldHold(true, m, now.Add(10*time.Minute)) {
		t.Fatal("expired experiment released hold")
	}
}
func TestUnpairedDiagnosticCodeRejectsNonCodeAndPrivateDetails(t *testing.T) {
	for _, s := range []string{"USB_LAYOUT_UNCONFIRMED_DECLINED_OR_CHANGED", "UNPAIRED_ORIGINAL_STORE_UNVERIFIED"} {
		if diagnosticCode(s) != s {
			t.Fatal("fixed cause lost")
		}
	}
	for _, s := range []string{"C:\\private\\pairfile.plist", "unpaired metadata: details", strings.Repeat("A", 97), "raw-device-serial-201e"} {
		if diagnosticCode(s) != "NON_CODE_DETAIL_REDACTED" {
			t.Fatal("private text escaped code whitelist")
		}
	}
}

func TestUnpairedMetadataCauseCodeAndDigestWhitelist(t *testing.T) {
	if unpairedMetadataFailureCode("PAIR_METADATA_CHECK: UNPAIRED_ORIGINAL_STORE_UNVERIFIED") != "UNPAIRED_ORIGINAL_STORE_UNVERIFIED" || unpairedMetadataFailureCode("ONE_ATTEMPT_COMPLETE") != "" {
		t.Fatal("wrong metadata cause extraction")
	}
	if unpairedMetadataFailureCode("PAIR_METADATA_CHECK: C:\\private") != "NON_CODE_DETAIL_REDACTED" {
		t.Fatal("metadata path leaked")
	}
	if diagnosticDigest(strings.Repeat("a", 64)) == "" || diagnosticDigest("private-serial-201e") != "" {
		t.Fatal("descriptor digest output lost bounds")
	}
}
