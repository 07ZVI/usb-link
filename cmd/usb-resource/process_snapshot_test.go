package main

import (
	"encoding/binary"
	"testing"
)

func TestBatchProcessSnapshotBoundsAndIdentity(t *testing.T) {
	b := make([]byte, 528)
	base := uint64(4096)
	binary.LittleEndian.PutUint32(b, 264)
	binary.LittleEndian.PutUint32(b[4:], 7)
	binary.LittleEndian.PutUint64(b[80:], 123)
	binary.LittleEndian.PutUint64(b[88:], 100)
	binary.LittleEndian.PutUint16(b[56:], 6)
	binary.LittleEndian.PutUint16(b[58:], 8)
	binary.LittleEndian.PutUint64(b[64:], base+256)
	for i, c := range []uint16{'U', 'S', 'B'} {
		binary.LittleEndian.PutUint16(b[256+2*i:], c)
	}
	binary.LittleEndian.PutUint64(b[264+80:], 456)
	binary.LittleEndian.PutUint64(b[264+88:], 123)
	rows, err := decodeProcessSnapshot(b, base)
	if err != nil || len(rows) != 2 || rows[0].name != "USB" || rows[0].threads != 7 || rows[1].parent != 123 {
		t.Fatal(rows, err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b, 4) },
		func(b []byte) { binary.LittleEndian.PutUint32(b, 1024) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 5) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[64:], base-1) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[64:], base+527) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[264+80:], 123) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[80:], 1<<40) },
	} {
		bad := append([]byte(nil), b...)
		mutate(bad)
		if _, err := decodeProcessSnapshot(bad, base); err == nil {
			t.Fatal("bad snapshot accepted")
		}
	}
	if _, err := decodeProcessSnapshot(b[:255], base); err == nil {
		t.Fatal("short header accepted")
	}
}
