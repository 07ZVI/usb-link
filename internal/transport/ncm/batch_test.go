package ncm

import (
	"bytes"
	"testing"
)

func TestBatchRespectsActualDeviceLimits(t *testing.T) {
	p := Parameters{OutMax: 32764, OutDivisor: 4, OutAlignment: 4, OutDatagrams: 512}
	n, err := BatchLimit(p, 1514, 32)
	if err != nil || n != 21 {
		t.Fatalf("limit=%d err=%v", n, err)
	}
	frames := make([][]byte, n)
	for i := range frames {
		frames[i] = bytes.Repeat([]byte{byte(i)}, 1514)
	}
	b, err := Encode(frames, 65535, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(b)
	if err != nil || len(decoded.Frames) != n {
		t.Fatal(decoded, err)
	}
	for i := range frames {
		if !bytes.Equal(frames[i], decoded.Frames[i]) {
			t.Fatal("batch reorders/corrupts frames")
		}
	}
	p.OutDatagrams = 3
	n, err = BatchLimit(p, 1514, 32)
	if err != nil || n != 3 {
		t.Fatal(n, err)
	}
	p.OutMax = 64
	if _, err = BatchLimit(p, 1514, 32); err == nil {
		t.Fatal("accepted frame larger than advertised NTB")
	}
}

func TestReadyBatchDoesNotWaitAndPreservesBound(t *testing.T) {
	ready := make(chan []byte, 4)
	for i := byte(2); i <= 5; i++ {
		ready <- []byte{i}
	}
	packets := ReadyBatch([]byte{1}, ready, 3)
	if len(packets) != 3 || packets[0][0] != 1 || packets[1][0] != 2 || packets[2][0] != 3 || len(ready) != 2 {
		t.Fatal(packets, len(ready))
	}
	if len(ReadyBatch([]byte{1}, make(chan []byte), 16)) != 1 {
		t.Fatal("empty queue should send immediately")
	}
	close(ready)
	if len(ReadyBatch([]byte{1}, ready, 16)) != 3 {
		t.Fatal("closed queue should return without spinning")
	}
}
