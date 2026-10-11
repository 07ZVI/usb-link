package ncm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestMaximumDatagramRollbackAndReadback(t *testing.T) {
	for _, scenario := range []string{"success", "short GET", "SET ambiguous", "readback mismatch", "restore fails", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			value := uint16(1514)
			writes := 0
			reads := 0
			transfer := func(rt, r byte, v, i uint16, b []byte) (int, error) {
				if v != 0 || i != 2 || len(b) != 2 {
					t.Fatal("request ABI")
				}
				switch r {
				case 0x87:
					if rt != 0xa1 {
						t.Fatal(rt)
					}
					reads++
					if scenario == "readback mismatch" && reads == 2 {
						binary.LittleEndian.PutUint16(b, 1514)
					} else {
						binary.LittleEndian.PutUint16(b, value)
					}
					if scenario == "short GET" {
						return 1, nil
					}
				case 0x88:
					if rt != 0x21 {
						t.Fatal(rt)
					}
					writes++
					value = binary.LittleEndian.Uint16(b)
					if scenario == "SET ambiguous" || scenario == "restore fails" {
						if writes == 1 || scenario == "restore fails" {
							return 0, fmt.Errorf("failed")
						}
					}
				default:
					t.Fatal(r)
				}
				return 2, nil
			}
			cap := byte(8)
			if scenario == "unsupported" {
				cap = 0
			}
			d, e := TryDatagram(transfer, 2, cap, 16014)
			switch scenario {
			case "success":
				if e != nil || d == nil || !d.Changed || value != 16014 {
					t.Fatal(d, e)
				}
				if e = d.Restore(transfer, 2, 16014); e != nil || d.Changed || value != 1514 {
					t.Fatal(d, e)
				}
			case "short GET":
				if e == nil || d != nil || writes != 0 {
					t.Fatal(d, e, writes)
				}
			case "SET ambiguous", "readback mismatch":
				if e == nil || d != nil || value != 1514 || writes != 2 {
					t.Fatal(d, e, writes, value)
				}
			case "restore fails":
				if e == nil || d == nil || !d.Changed {
					t.Fatal("unsafe failure lost", d, e)
				}
			case "unsupported":
				if e != nil || d != nil || writes != 0 {
					t.Fatal(d, e)
				}
			}
		})
	}
}
func TestAlreadyLargeFrameDoesNotImplyIPMTU(t *testing.T) {
	writes := 0
	d, e := TryDatagram(func(rt, r byte, v, i uint16, b []byte) (int, error) {
		if r != 0x87 {
			writes++
		}
		binary.LittleEndian.PutUint16(b, 16014)
		return 2, nil
	}, 0, 8, 16014)
	if e != nil || d == nil || d.Changed || writes != 0 {
		t.Fatal(d, e, writes)
	}
}
