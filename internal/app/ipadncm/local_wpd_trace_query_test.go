package ipadncm

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func wpdQueryFixture(name, file string) []byte {
	b := make([]byte, 4216)
	for _, s := range []struct {
		at   int
		text string
	}{{120, name}, {2168, file}} {
		for i, v := range utf16.Encode([]rune(s.text)) {
			binary.LittleEndian.PutUint16(b[s.at+i*2:], v)
		}
	}
	return b
}

func TestWPDQueryOutputOffsetsAreNotFileLogging(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	raw := wpdQueryFixture(j.Session, "")
	for _, offset := range []uint32{0, 2168} {
		if d := wpdCheckSessionQuery(j, "", raw, true, 0x10000100, 0, 120, offset); d.Mismatch != 0 {
			t.Fatal(d)
		}
	}
	j.Schema, j.Mode, j.File = 1, "", localWPDTraceETLFile
	path := `C:\protected\local-wpd-trace.etl`
	if d := wpdCheckSessionQuery(j, path, wpdQueryFixture(j.Session, path), true, 0x10000102, 8, 120, 2168); d.Mismatch != 0 {
		t.Fatal("legacy recovery rejected", d)
	}
}

func TestWPDQueryOwnershipRejectsMalformedAndForeign(t *testing.T) {
	j := cleanupWPDMetadataFixture()
	for _, tc := range []struct {
		name                                     string
		edit                                     func([]byte)
		guid                                     bool
		mode, size, nameOffset, fileOffset, bits uint32
	}{
		{"guid", nil, false, 0x10000100, 0, 120, 2168, 1},
		{"foreign_name", func(b []byte) { b[120] = 'X' }, true, 0x10000100, 0, 120, 2168, 4},
		{"header_name", nil, true, 0x10000100, 0, 0, 2168, 2},
		{"odd_file", nil, true, 0x10000100, 0, 120, 2169, 8},
		{"outside_file", nil, true, 0x10000100, 0, 120, 4216, 8},
		{"unterminated_file", func(b []byte) {
			for i := 2168; i < len(b); i += 2 {
				b[i] = 'x'
			}
		}, true, 0x10000100, 0, 120, 2168, 8},
		{"invalid_utf16", func(b []byte) { binary.LittleEndian.PutUint16(b[2168:], 0xd800) }, true, 0x10000100, 0, 120, 2168, 8},
		{"file_present", func(b []byte) { b[2168] = 'x' }, true, 0x10000100, 0, 120, 2168, 16},
		{"file_mode", nil, true, 0x10000102, 0, 120, 2168, 16},
		{"max_file", nil, true, 0x10000100, 8, 120, 2168, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := wpdQueryFixture(j.Session, "")
			if tc.edit != nil {
				tc.edit(b)
			}
			d := wpdCheckSessionQuery(j, "", b, tc.guid, tc.mode, tc.size, tc.nameOffset, tc.fileOffset)
			if d.Mismatch != tc.bits {
				t.Fatal(d)
			}
		})
	}
}
