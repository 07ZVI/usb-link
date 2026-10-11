package macconnection

import (
	"bytes"
	"io"
	"testing"
)

type readAtOnly struct {
	data    []byte
	largest int
}

func (r *readAtOnly) ReadAt(b []byte, off int64) (int, error) {
	if len(b) > r.largest {
		r.largest = len(b)
	}
	return bytes.NewReader(r.data).ReadAt(b, off)
}
func TestArchiveReaderRetainsOwnershipChecksWithoutWholePayloadRead(t *testing.T) {
	data, manifest, hash, _ := concurrentRuntimeFixture(t)
	reader := &readAtOnly{data: data}
	parent := t.TempDir()
	first, e := unpackArchiveRuntime(parent, RuntimeArchive{reader, int64(len(data))}, manifest, hash)
	if e != nil {
		t.Fatal(e)
	}
	again, e := unpackArchiveRuntime(parent, RuntimeArchive{reader, int64(len(data))}, manifest, hash)
	if e != nil || first != again {
		t.Fatal(e)
	}
	if reader.largest >= len(data) || reader.largest > 64<<10 {
		t.Fatal("whole archive requested", reader.largest, len(data))
	}
	if _, e = unpackArchiveRuntime(parent, RuntimeArchive{reader, int64(len(data) - 1)}, manifest, hash); e == nil {
		t.Fatal("truncated archive accepted")
	}
	if _, e = unpackArchiveRuntime(parent, RuntimeArchive{reader, 65 << 20}, manifest, hash); e == nil {
		t.Fatal("unbounded archive accepted")
	}
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 1
	if _, e = unpackArchiveRuntime(parent, RuntimeArchive{bytes.NewReader(corrupt), int64(len(corrupt))}, manifest, hash); e == nil || e == io.EOF {
		t.Fatal("changed archive accepted", e)
	}
}
