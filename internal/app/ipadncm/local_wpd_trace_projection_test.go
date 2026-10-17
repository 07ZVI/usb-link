//go:build usblink_local_remote

package ipadncm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func wpdProjectionFixture(id uint16) []byte {
	// Private command parameter, private response parameter and private body.
	b := make([]byte, 18)
	copy(b[:8], []byte("SECRETS!"))
	binary.LittleEndian.PutUint16(b[8:], 0x1002)
	binary.LittleEndian.PutUint32(b[10:], 1)
	copy(b[14:], []byte("PRIV"))
	if id == 2000 {
		return b
	}
	b = append(b, make([]byte, 18)...)
	binary.LittleEndian.PutUint32(b[18:], 0x80004005)
	binary.LittleEndian.PutUint16(b[22:], 0x2001)
	binary.LittleEndian.PutUint32(b[24:], 1)
	copy(b[28:], []byte("PAIR"))
	secret := []byte("PRIVATE_PAIRING_CERTIFICATE_AND_FILENAME")
	binary.LittleEndian.PutUint32(b[32:], uint32(len(secret)))
	return append(b, secret...)
}
func TestWPDProjectionNeverReadsPrivateRanges(t *testing.T) {
	for _, id := range []uint16{2000, 2001} {
		b := wpdProjectionFixture(id)
		permitted := map[int]int{8: 2, 10: 4}
		if id == 2001 {
			permitted[18] = 4
			permitted[22] = 2
			permitted[24] = 4
			permitted[32] = 4
		}
		code, response, stage := wpdProjectMTP(id, uint16(len(b)), func(off, size int) uint64 {
			if permitted[off] != size {
				t.Fatalf("private read %d/%d", off, size)
			}
			if size == 2 {
				return uint64(binary.LittleEndian.Uint16(b[off:]))
			}
			return uint64(binary.LittleEndian.Uint32(b[off:]))
		})
		if stage != "decoded" || code != 0x1002 {
			t.Fatal(code, stage)
		}
		if id == 2001 && (!response.CodeRead || response.Code != 0x2001 || !response.TransportRead || response.TransportHR != 0x80004005) {
			t.Fatal(response)
		}
		e := localWPDTraceEvent{Provider: "mtp", EventID: id, CommandField: "MTP_Opcode", CommandCode: uint64(code), OpcodeDecoded: true, Response: response}
		out, _ := json.Marshal(e)
		for _, secret := range [][]byte{[]byte("SECRETS"), []byte("PRIV"), []byte("PAIR"), b[14:18]} {
			if bytes.Contains(out, secret) {
				t.Fatal("private content persisted")
			}
		}
	}
}
func TestWPDProjectionRejectsLengthsBeforeUnsafeReads(t *testing.T) {
	b := wpdProjectionFixture(2001)
	for n := 0; n < len(b); n++ {
		_, _, stage := wpdProjectMTP(2001, uint16(n), func(off, size int) uint64 {
			if off < 0 || off+size > n {
				t.Fatalf("out of bounds %d %d length%d", off, size, n)
			}
			if size == 2 {
				return uint64(binary.LittleEndian.Uint16(b[off:]))
			}
			return uint64(binary.LittleEndian.Uint32(b[off:]))
		})
		if stage == "decoded" {
			t.Fatal("truncated accepted", n)
		}
	}
	for _, offset := range []int{10, 24, 32} {
		altered := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(altered[offset:], 0xffffffff)
		_, _, stage := wpdProjectMTP(2001, uint16(len(altered)), func(off, size int) uint64 {
			if off+size > len(altered) {
				t.Fatal("unsafe count")
			}
			if size == 2 {
				return uint64(binary.LittleEndian.Uint16(altered[off:]))
			}
			return uint64(binary.LittleEndian.Uint32(altered[off:]))
		})
		if stage == "decoded" {
			t.Fatal("oversized array admitted")
		}
	}
}
func TestWPDProjectionRequiresEveryInstalledVersion(t *testing.T) {
	fixtures := wpdMTPFixtures(t)
	read := func(d [16]byte) []byte { b := wpdMTPMetadata(2000, fixtures[2000]); copy(b[32:48], d[:]); return b }
	if got := wpdProjectionDefinitions("mtp", privacyEnumeration(0), read); len(got) != 1 {
		t.Fatal(got)
	}
	for _, versions := range [][]byte{{0, 1}, {0, 0}} {
		if len(wpdProjectionDefinitions("mtp", privacyEnumeration(versions...), read)) != 0 {
			t.Fatal("unsafe versions admitted")
		}
	}
	for _, provider := range []string{"api", "usb", "unknown"} {
		if len(wpdProjectionDefinitions(provider, privacyEnumeration(0), read)) != 0 {
			t.Fatal(provider)
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[124:], 1) }, func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 1) }, func(b []byte) { binary.LittleEndian.PutUint16(b[120:], 1) }} {
		if len(wpdProjectionDefinitions("mtp", privacyEnumeration(0), func(d [16]byte) []byte { b := read(d); mutate(b); return b })) != 0 {
			t.Fatal("unknown schema admitted")
		}
	}
}
func TestWPDProjectionQueueRetainsOnlyScalarsAndHonorsClose(t *testing.T) {
	q := newWPDCriticalQueue()
	original := wpdCriticalItem{projected: true, event: localWPDTraceEvent{Provider: "mtp", CommandCode: 0x1002, OpcodeDecoded: true}, stage: "decoded"}
	for i := 0; i < wpdCriticalCapacity; i++ {
		if reason := q.enqueue(wpdCriticalCapture{summary: true, headerSize: 80}, func(dst *wpdCriticalItem) { *dst = original }); reason != "" {
			t.Fatal(reason)
		}
	}
	if reason := q.enqueue(wpdCriticalCapture{summary: true, headerSize: 80}, func(*wpdCriticalItem) { t.Fatal("overflow fill") }); reason != "queue_full" {
		t.Fatal(reason)
	}
	q.close()
	if reason := q.enqueue(wpdCriticalCapture{summary: true, headerSize: 80}, func(*wpdCriticalItem) { t.Fatal("late callback fill") }); reason != "consumer_closed" {
		t.Fatal(reason)
	}
	for i := 0; i < wpdCriticalCapacity; i++ {
		item, found, _ := q.pop()
		if !found || item.payload != ([wpdCriticalPayloadLimit]byte{}) || item.header != ([80]byte{}) || item.event.CommandCode != 0x1002 {
			t.Fatal("raw retained or lost projection")
		}
		q.complete(true, false, true)
	}
	s := q.snapshot()
	if s.Pending != 0 || s.InFlight != 0 || s.Overflow != 1 || s.Rejected != 1 || !s.Closed {
		t.Fatal(s)
	}
}

func TestWPDProjectionFailuresCountWithoutPayload(t *testing.T) {
	var s localWPDTraceSample
	for _, stage := range []string{"strict_manifest_template_mismatch", "version_not_selected", "payload_size_invalid", "payload_layout_invalid"} {
		s.recordDecode(localWPDTraceSchema{Provider: "mtp", Stage: stage})
	}
	if s.DecodeCounts.Attempted != 4 || s.DecodeCounts.InvalidMetadata != 1 || s.DecodeCounts.NoCandidate != 1 || s.DecodeCounts.SizeFailed != 1 || s.DecodeCounts.SizeMismatch != 1 {
		t.Fatal(s.DecodeCounts)
	}
}
