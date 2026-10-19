package ncm

import (
	"encoding/binary"
	"testing"
)

func TestParseMTUCap(t *testing.T) {
	for in, want := range map[string]MTUCap{"": MTUCapAuto, "auto": MTUCapAuto, "9000": MTUCap9000, "1500": MTUCap1500} {
		got, err := ParseMTUCap(in)
		if err != nil || got != want {
			t.Fatal(in, got, err)
		}
		if again, _ := ParseMTUCap(got.String()); again != got {
			t.Fatal("round trip", in)
		}
	}
	for _, bad := range []string{"AUTO", "16000", "0", "1501", " 9000", "9000 "} {
		if _, err := ParseMTUCap(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestMTUCapFrameLimits(t *testing.T) {
	cases := []struct {
		cap                     MTUCap
		ceiling, maxMTU         int
		jumbo                   bool
		segment, current, batch int
		trial                   int
	}{
		{MTUCapAuto, 16014, 16000, true, 16014, 16014, 16014, 16014},
		{MTUCap9000, 9014, 9000, true, 16014, 16014, 16014, 9014},
		{MTUCap1500, 1514, 1500, false, 16014, 16014, 16014, 1514},
		{MTUCap9000, 9014, 9000, true, 4000, 1514, 1514, 1514},
		{MTUCap9000, 9014, 9000, true, 9014, 9014, 9014, 9014},
		{MTUCapAuto, 16014, 16000, true, 9014, 9014, 9014, 9014},
	}
	for _, c := range cases {
		if c.cap.FrameCeiling() != c.ceiling || c.cap.MaxMTU() != c.maxMTU || c.cap.AllowsJumbo() != c.jumbo {
			t.Fatal(c)
		}
		if got := c.cap.DeviceMaxSegment(c.segment); got > c.segment || got > c.ceiling {
			t.Fatal("segment exceeds device or cap", c, got)
		}
		if got := c.cap.TrialFrameLimit(c.current, c.batch); got != c.trial {
			t.Fatal("trial limit", c, got)
		}
	}
}

func datagramDevice(initial uint16, writes *[]uint16) ControlTransfer {
	value := initial
	return func(rt, r byte, v, i uint16, b []byte) (int, error) {
		if r == 0x87 {
			binary.LittleEndian.PutUint16(b, value)
			return 2, nil
		}
		value = binary.LittleEndian.Uint16(b)
		*writes = append(*writes, value)
		return 2, nil
	}
}

func TestTryDatagramCapped(t *testing.T) {
	for _, c := range []struct {
		cap    MTUCap
		writes []uint16
		cur    uint16
	}{{MTUCapAuto, []uint16{16014}, 16014}, {MTUCap9000, []uint16{9014}, 9014}, {MTUCap1500, nil, 0}} {
		var writes []uint16
		d, err := TryDatagramCapped(datagramDevice(1514, &writes), 0, 8, 16014, c.cap)
		if err != nil {
			t.Fatal(err)
		}
		if c.cap == MTUCap1500 {
			if d != nil || len(writes) != 0 {
				t.Fatal("1500 cap must not touch the device", d, writes)
			}
			continue
		}
		if d == nil || d.Current != c.cur || len(writes) != 1 || writes[0] != c.writes[0] {
			t.Fatal(c.cap, d, writes)
		}
	}
	// A smaller device maximum still wins over the cap.
	var writes []uint16
	d, err := TryDatagramCapped(datagramDevice(1514, &writes), 0, 8, 9014, MTUCapAuto)
	if err != nil || d == nil || d.Current != 9014 {
		t.Fatal(d, err)
	}
}
