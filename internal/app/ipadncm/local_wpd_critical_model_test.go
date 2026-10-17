//go:build usblink_local_remote

package ipadncm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestWPDCriticalTemplateRequiresCapturedProviderAndExactSchema(t *testing.T) {
	provider := [16]byte{1, 2, 3, 4}
	for id, fields := range wpdMTPFixtures(t) {
		m := wpdMTPMetadata(id, fields)
		copy(m[:16], provider[:])
		if got := wpdCriticalTemplateStage(provider, id, 0, m); got != "" {
			t.Fatal(id, got)
		}
		for _, change := range []func([]byte){func(m []byte) { m[0] ^= 1 }, func(m []byte) { m[32] ^= 1 }, func(m []byte) { m[34] = 1 }, func(m []byte) { m[48] = 1 }} {
			bad := append([]byte(nil), m...)
			change(bad)
			if wpdCriticalTemplateStage(provider, id, 0, bad) == "" {
				t.Fatal("changed metadata admitted")
			}
		}
		if wpdCriticalTemplateStage([16]byte{}, id, 0, m) == "" || wpdCriticalTemplateStage(provider, id, 1, m) == "" || wpdCriticalTemplateStage(provider, 2004, 0, m) == "" {
			t.Fatal("unknown identity admitted")
		}
		for i := range fields {
			altered := append([]wpdManifestField(nil), fields...)
			altered[i].Name += "Changed"
			bad := wpdMTPMetadata(id, altered)
			copy(bad[:16], provider[:])
			if wpdCriticalTemplateStage(provider, id, 0, bad) == "" {
				t.Fatal("partial template accepted", i)
			}
		}
	}
}
func TestWPDCriticalCorrelationNeverExportsActivityOrDeviceIdentity(t *testing.T) {
	var raw [80]byte
	binary.LittleEndian.PutUint32(raw[8:], 42)
	zero := wpdCriticalHeaderCorrelation(raw)
	if zero.ThreadID != 42 || zero.ActivityPresent || zero.ActivitySHA256 != "" || zero.Attribution != "system_unattributed" || zero.RelatedActivityStatus != "not_collected" {
		t.Fatal(zero)
	}
	copy(raw[64:], []byte("private-activity"))
	sum := sha256.Sum256(raw[64:80])
	got := wpdCriticalHeaderCorrelation(raw)
	if !got.ActivityPresent || got.ActivitySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal(got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "private-activity") {
		t.Fatal("raw activity exported")
	}
	copy := got
	raw[64] ^= 1
	if got != copy || wpdCriticalHeaderCorrelation(raw).ActivitySHA256 == got.ActivitySHA256 {
		t.Fatal("correlation alias")
	}
}

func TestWPDCapturedRecordShapeIsBoundedScalarEvidence(t *testing.T) {
	item := wpdCriticalItem{length: 2}
	binary.LittleEndian.PutUint16(item.header[:2], 112)
	binary.LittleEndian.PutUint16(item.header[4:6], 576)
	copy(item.payload[:], "private-data")
	got := item.recordShape()
	if got != (wpdRecordShape{RecordBytes: 112, HeaderBytes: 80, UserDataBytes: 2, HeaderFlags: 576}) {
		t.Fatal(got)
	}
	b, e := json.Marshal(got)
	if e != nil || len(b) > 128 || strings.Contains(string(b), "private-data") {
		t.Fatal(string(b), e)
	}
}
