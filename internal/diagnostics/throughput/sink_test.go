package throughput

import (
	"io"
	"testing"
)

type sizeRecorder struct {
	left, max int
}

func (r *sizeRecorder) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	r.max = max(r.max, len(p))
	n := min(len(p), r.left)
	r.left -= n
	return n, nil
}

func TestUploadSinkHonoursCopyBuffer(t *testing.T) {
	r := &sizeRecorder{left: ChunkBytes}
	n, err := io.CopyBuffer(uploadSink{}, r, make([]byte, 64*1024))
	if err != nil || n != ChunkBytes || r.max != 64*1024 {
		t.Fatal(n, err, r.max)
	}
	r = &sizeRecorder{left: ChunkBytes}
	io.CopyBuffer(io.Discard, r, make([]byte, 64*1024))
	if r.max == 64*1024 {
		t.Skip("io.Discard now honours the buffer; sink is harmless")
	}
}
