package ipadncm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func config(ds ...[]byte) []byte {
	b := []byte{9, 2, 0, 0, 2, 5, 0, 0x80, 50}
	for _, d := range ds {
		b = append(b, d...)
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func TestFunctionalMetadataPreservesMalformedLengthsWithoutIdentifiers(t *testing.T) {
	b := config([]byte{9, 4, 2, 0, 1, 2, 13, 0, 0},
		[]byte{5, 0x24, 0, 0x20, 1},
		[]byte{13, 0x24, 0x0f, 0x77, 0, 0, 0, 0, 0xea, 5, 0, 0, 0},
		[]byte{6, 0x24, 0x1a, 0, 1, 0x11},
		[]byte{3, 0x24, 0x1a})
	c, e := Parse(b, 0)
	if e != nil {
		t.Fatal(e)
	}
	f := c.Interfaces[0].Functions
	if len(f) != 4 || *f[0].Version != 0x120 || *f[1].MaxSegment != 1514 || *f[2].Version != 0x100 || *f[2].Capabilities != 0x11 || f[3].Length != 3 || f[3].Version != nil {
		t.Fatalf("functional metadata: %+v", f)
	}
	encoded, _ := json.Marshal(f)
	if bytes.Contains(encoded, []byte("119")) || bytes.Contains(encoded, []byte("mac")) {
		t.Fatalf("exported ethernet string index: %s", encoded)
	}
}
func TestNCMControlDataAndMissingInterrupt(t *testing.T) {
	b := config([]byte{9, 4, 2, 0, 0, 2, 13, 0, 0}, []byte{5, 0x24, 6, 2, 3}, []byte{9, 4, 3, 1, 2, 10, 0, 1, 0}, []byte{7, 5, 0x81, 2, 0, 4, 0}, []byte{7, 5, 2, 2, 0, 4, 0})
	c, e := Parse(b, 0)
	if e != nil || c.NCMControls != 1 || c.Value != 5 || len(c.Interfaces) != 2 || c.Interfaces[0].Slaves[0] != 3 || len(c.Interfaces[0].Endpoints) != 0 || len(c.Interfaces[1].Endpoints) != 2 {
		t.Fatalf("parse: %+v %v", c, e)
	}
}
func TestRejectMalformedDescriptors(t *testing.T) {
	for _, b := range [][]byte{nil, {9, 2}, config([]byte{0, 4}), config([]byte{9, 4, 0}), config([]byte{7, 5, 1, 2, 0, 4, 0}), config([]byte{9, 4, 2, 0, 0, 2, 13, 0, 0}, []byte{5, 0x24, 6, 1, 3})} {
		if _, e := Parse(b, 0); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	b := config([]byte{9, 4, 0, 0, 0, 255, 254, 2, 0})
	c, e := Parse(b, 0)
	if e != nil || c.NCMControls != 0 {
		t.Fatal("vendor interface mistaken for NCM")
	}
	for i := 0; i < len(b); i++ {
		if _, e := Parse(b[:i], 0); e == nil {
			t.Fatal("accepted truncation")
		}
	}
}

func TestAssociationAndActiveConfiguration(t *testing.T) {
	b := config([]byte{8, 0x0b, 2, 2, 2, 13, 0, 9}, []byte{9, 4, 2, 0, 0, 2, 13, 0, 0}, []byte{5, 0x24, 6, 2, 3}, []byte{9, 4, 3, 0, 0, 10, 0, 1, 0})
	c, e := Parse(b, 4)
	if e != nil || len(c.Associations) != 1 || c.Associations[0].First != 2 || c.Associations[0].Count != 2 {
		t.Fatalf("association: %+v %v", c, e)
	}
	// NCM advertised in an inactive configuration must not permit a start test.
	if activeNCM([]Configuration{c}, 3) || !activeNCM([]Configuration{c}, 5) {
		t.Fatal("advertised configuration confused with active NCM")
	}
	for _, d := range [][]byte{{7, 0x0b, 2, 2, 2, 13, 0}, {8, 0x0b, 2, 0, 2, 13, 0, 0}, {8, 0x0b, 255, 2, 2, 13, 0, 0}} {
		if _, e := Parse(config(d), 0); e == nil {
			t.Fatalf("accepted malformed association %x", d)
		}
	}
}
