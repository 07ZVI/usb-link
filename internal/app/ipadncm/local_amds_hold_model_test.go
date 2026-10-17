package ipadncm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalAMDSHoldJournalBoundAndOriginals(t *testing.T) {
	j := localAMDSHoldJournal{Schema: 1, Service: localAMDSHoldService, OriginalState: 4, StartType: 2, ConfigHash: strings.Repeat("a", 64)}
	b, _ := json.Marshal(j)
	if _, e := decodeLocalAMDSHoldJournal(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), localAMDSHoldService, "OtherService", 1), strings.Replace(string(b), `"original_state":4`, `"original_state":2`, 1), strings.Replace(string(b), `"start_type":2`, `"start_type":0`, 1), string(b) + "{}", strings.Repeat(" ", 4097) + string(b)} {
		if _, e := decodeLocalAMDSHoldJournal([]byte(bad)); e == nil {
			t.Fatal("invalid original accepted")
		}
	}
	s := localAMDSHoldStatus{Available: true, Requested: true, Effective: true, RequestID: strings.Repeat("a", 32), RejectedID: strings.Repeat("b", 32), RejectedError: "AMDS_HOLD_DEBUG_REQUIRED", Error: "AMDS_HOLD_OPERATION_FAILED", CauseCode: "AMDS_HOLD_SERVICE_IDENTITY_UNPROVEN", NativeCode: ^uint32(0), RunID: strings.Repeat("c", 32), SampledUTC: "2026-10-17T00:00:00.123456789Z", SampledMS: 9223372036854775807, Persistence: "saved", Phase: "recovery_pending"}
	s.Identity = &localAMDSHoldIdentity{AbsoluteImage: true, BasenameMatch: true, Account: "network_service", ServiceType: ^uint32(0), HasArguments: true}
	b, _ = json.Marshal(s)
	if len(b) > 2048 || strings.Contains(string(b), j.ConfigHash) || strings.Contains(string(b), localAMDSHoldService) {
		t.Fatal(len(b), string(b))
	}
}
