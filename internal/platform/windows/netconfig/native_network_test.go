package netconfig

import (
	"encoding/binary"
	"testing"
)

func TestNativeNetworkDefaultsOff(t *testing.T) {
	if NativeNetworkEnabled() {
		t.Fatal("native network must default off")
	}
}

func TestNativeCategoryRequiresSavedOriginal(t *testing.T) {
	public, private := uint32(0), uint32(1)
	if !nativeCategoryAllows(0, 1, &public, false) {
		t.Fatal("unchanged saved original refused")
	}
	if nativeCategoryAllows(1, 1, &public, false) {
		t.Fatal("foreign change or unknown successful call adopted")
	}
	if !nativeCategoryAllows(1, 0, &private, true) || !nativeCategoryAllows(0, 0, &private, true) {
		t.Fatal("owned restore or idempotent original refused")
	}
	if nativeCategoryAllows(0, 1, &private, true) {
		t.Fatal("restore overwrites a user public change")
	}
	if nativeCategoryAllows(2, 1, nil, false) || nativeCategoryAllows(0, 2, nil, false) {
		t.Fatal("domain/unknown category accepted")
	}
}

func TestICMPBoundedReplyProof(t *testing.T) {
	_, dest, err := icmpPair("10.6.9.1", "10.6.9.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, e := icmpPair("10.6.9.1", "8.8.8.8"); e == nil {
		t.Fatal("foreign peer")
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	const base = uintptr(0x1fffffff0)
	for _, offset := range []uint32{28, 40} {
		r := make([]byte, 256)
		binary.LittleEndian.PutUint32(r[:4], dest)
		binary.LittleEndian.PutUint16(r[12:14], 32)
		binary.LittleEndian.PutUint32(r[16:20], uint32(uint64(base)+uint64(offset)))
		copy(r[offset:], nonce)
		if _, e := checkICMPEchoReply(r, nonce, base, dest); e != nil {
			t.Fatal(e)
		}
		for _, where := range []int{0, 4, 12, 16, int(offset)} {
			bad := append([]byte(nil), r...)
			bad[where] ^= 0x80
			if _, e := checkICMPEchoReply(bad, nonce, base, dest); e == nil {
				t.Fatalf("accepted corrupt field %d", where)
			}
		}
	}
}
