//go:build usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWPDPrivacyRejectsActualInstalled35Templates(t *testing.T) {
	// These are recorded installed definitions, not a hypothetical scalar-only
	// event. Numeric arrays are not presumed free of private command parameters.
	for id, fields := range wpdMTPFixtures(t) {
		if wpdWholeEventSafe(wpdMTPMetadata(id, fields)) {
			t.Fatal("raw command/response admitted", id)
		}
	}
	for _, fields := range [][]wpdManifestField{
		{{"MTPUSLength", 8, 8, 0, 1, 4}, {"MTPUSData", 14, 15, 2, 1, 0}},
		{{"SessionID", 8, 8, 0, 1, 4}, {"TransactionID", 8, 8, 0, 1, 4}, {"MTP_Event_Retrieval_HR_From_Transport", 8, 8, 0, 1, 4}, {"MTP_Event_Code", 6, 6, 0, 1, 2}, {"MTP_Event_Param_count", 8, 8, 0, 1, 4}, {"MTP_Event_Params", 8, 8, 4, 4, 4}},
	} {
		if wpdWholeEventSafe(manifestFixture(fields)) {
			t.Fatal("installed unsafe template admitted")
		}
	}
}

func TestWPDPrivacyWholeSafeScalarAndMalformed(t *testing.T) {
	safe := []wpdManifestField{{"MTP_Opcode", 6, 6, 0, 1, 2}, {"MTP_Response_Code", 6, 6, 0, 1, 2}, {"MTP_Response_Retrieval_HR_From_Transport", 8, 8, 0, 1, 4}}
	if !wpdWholeEventSafe(manifestFixture(safe)) {
		t.Fatal("complete safe scalar template rejected")
	}
	for _, bad := range []wpdManifestField{
		{"MTP_Opcode", 1, 1, 0, 1, 2}, {"MTP_Opcode", 14, 15, 0, 1, 2}, {"MTP_Opcode", 6, 6, 4, 1, 2},
		{"MTP_Opcode", 6, 6, 0, 2, 2}, {"MTP_Opcode", 6, 6, 0, 1, 4}, {"UnknownNumericPayload", 6, 6, 0, 1, 2},
	} {
		f := append([]wpdManifestField(nil), safe...)
		f[0] = bad
		if wpdWholeEventSafe(manifestFixture(f)) {
			t.Fatal("unsafe field admitted", bad)
		}
	}
	b := manifestFixture(safe)
	mapped := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(mapped[124:], 1)
	if wpdWholeEventSafe(mapped) {
		t.Fatal("unreviewed value map")
	}
	for _, end := range []int{0, 111, 112, 140, len(b) - 1} {
		if wpdWholeEventSafe(b[:end]) {
			t.Fatal("truncation admitted", end)
		}
	}
	if wpdWholeEventSafe(manifestFixture(nil)) {
		t.Fatal("empty proof admitted")
	}
}

func privacyEnumeration(versions ...byte) []byte {
	b := make([]byte, 8+16*len(versions))
	binary.LittleEndian.PutUint32(b, uint32(len(versions)))
	for i, v := range versions {
		binary.LittleEndian.PutUint16(b[8+i*16:], 2000)
		b[10+i*16] = v
	}
	return b
}
func TestWPDPrivacyAllVersionsBeforeNativeIDFilter(t *testing.T) {
	reads := 0
	read := func(d [16]byte) []byte {
		reads++
		b := manifestFixture([]wpdManifestField{{"MTP_Opcode", 6, 6, 0, 1, 2}})
		copy(b[32:48], d[:])
		return b
	}
	ids := wpdSafeEventIDs("mtp", privacyEnumeration(0, 1), read)
	if !reflect.DeepEqual(ids, []uint16{2000}) || reads != 2 {
		t.Fatal(ids, reads)
	}
	unsafeRead := func(d [16]byte) []byte {
		b := read(d)
		if d[2] == 1 {
			b = wpdMTPMetadata(2000, wpdMTPFixtures(t)[2000])
			copy(b[32:48], d[:])
		}
		return b
	}
	if len(wpdSafeEventIDs("mtp", privacyEnumeration(0, 1), unsafeRead)) != 0 {
		t.Fatal("unsafe later version admitted")
	}
	for _, b := range [][]byte{privacyEnumeration(0, 0), privacyEnumeration(0)[:9], append(privacyEnumeration(0), 0)} {
		if len(wpdSafeEventIDs("mtp", b, read)) != 0 {
			t.Fatal("ambiguous/malformed enumeration")
		}
	}
	if len(wpdSafeEventIDs("api", privacyEnumeration(0), read)) != 0 {
		t.Fatal("wrong provider")
	}
	filter := wpdEventIDFilter(ids)
	if !reflect.DeepEqual(filter, []byte{1, 0, 1, 0, 0xd0, 7}) {
		t.Fatal(filter)
	}
	for _, ids := range [][]uint16{nil, {0}, {2000, 2000}, make([]uint16, 65)} {
		if wpdEventIDFilter(ids) != nil {
			t.Fatal("unsafe native filter")
		}
	}
}

func TestWPDMetadataJournalAndRecoveryOwnership(t *testing.T) {
	j := localWPDTraceJournal{Schema: 2, Mode: "metadata_session", Session: "USBLink-WPD-" + strings.Repeat("a", 32), GUID: "{12345678-1234-1234-1234-123456789abc}", OwnerSID: "S-1-5-18"}
	b, _ := json.Marshal(j)
	if _, e := decodeLocalWPDTraceJournal(b); e != nil {
		t.Fatal(e)
	}
	if !wpdSessionModeOwned(j, 0x10000100, 0, "", "") {
		t.Fatal("own metadata session")
	}
	for _, mode := range []uint32{2, 0x10000102, 0x100, 0x10000101} {
		if wpdSessionModeOwned(j, mode, 0, "", "") {
			t.Fatal("foreign file mode accepted", mode)
		}
	}
	if wpdSessionModeOwned(j, 0x10000100, 8, "", "") || wpdSessionModeOwned(j, 0x10000100, 0, "foreign.etl", "") {
		t.Fatal("file output accepted")
	}
	j.File = localWPDTraceETLFile
	if j.valid() {
		t.Fatal("schema2 file")
	}
	j.Schema = 1
	j.Mode = ""
	if !j.valid() || !wpdSessionModeOwned(j, 0x10000102, 8, "old.etl", "old.etl") {
		t.Fatal("legacy recovery broken")
	}
	if wpdSessionModeOwned(j, 0x10000102, 8, "foreign.etl", "old.etl") {
		t.Fatal("foreign legacy path")
	}
	j.Mode = "metadata_session"
	if j.valid() {
		t.Fatal("schema1 mode confusion")
	}
}

func TestWPDPrivacyNoNativeEnableOnUnsafeTemplates(t *testing.T) {
	calls := 0
	err := enableLocalWPDTraceProviders(func() bool { return true }, func(int) localWPDTraceProvider {
		return localWPDTraceProvider{Kind: "modern", SkipCode: "whole_event_not_safe"}
	}, func(int) uint32 { calls++; return 0 }, func(int, localWPDTraceProvider) {})
	if calls != 0 || err == nil || err.Error() != "WPD_TRACE_SAFE_METADATA_NOT_COVERED" {
		t.Fatal(calls, err)
	}
	s := newWPDTraceProviderSample()
	wire, _ := json.Marshal(s)
	if len(wire) > 4096 {
		t.Fatal(string(wire))
	}
}

func TestWPDMetadataHybridPolicyIsAnExactAllowlist(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	for _, mode := range []uint32{0x10000100, 0x10400100, 0x10800100} {
		if !wpdSessionModeOwned(j, mode, 0, "", "") {
			t.Fatalf("owned mode %08x rejected", mode)
		}
		for bit := uint(0); bit < 32; bit++ {
			changed := mode ^ (uint32(1) << bit)
			want := changed == 0x10000100 || changed == 0x10400100 || changed == 0x10800100
			if wpdSessionModeOwned(j, changed, 0, "", "") != want {
				t.Fatalf("unexpected mode %08x", changed)
			}
		}
		if wpdSessionModeOwned(j, mode, 8, "", "") || wpdSessionModeOwned(j, mode, 0, "foreign.etl", "") {
			t.Fatal("hybrid flag bypassed file ownership")
		}
		raw := wpdQueryFixture(j.Session, "")
		if d := wpdCheckSessionQuery(j, "", raw, true, mode, 0, 120, 2168); d.Mismatch != 0 {
			t.Fatal(d)
		}
		if d := wpdCheckSessionQuery(j, "", raw, false, mode, 0, 120, 2168); d.Mismatch != 1 {
			t.Fatal("hybrid flag bypassed GUID", d)
		}
		if d := wpdCheckSessionQuery(j, "", wpdQueryFixture("foreign", ""), true, mode, 0, 120, 2168); d.Mismatch != 4 {
			t.Fatal("hybrid flag bypassed name", d)
		}
	}
	if wpdMetadataModeOwned(0x10c00100) {
		t.Fatal("contradictory hybrid policies")
	}
}
