package connectioninstall

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type zeroStartupReader struct{ read int64 }

func (r *zeroStartupReader) Read(b []byte) (int, error) {
	clear(b)
	r.read += int64(len(b))
	return len(b), nil
}

type failedStartupReader struct{}

func (failedStartupReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type failedStartupWriter struct{}

func (failedStartupWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCanonicalStartupSourceRejectsWrongBytesAndBoundsRead(t *testing.T) {
	for _, source := range []io.Reader{nil, bytes.NewReader(nil), strings.NewReader("not the published executable"), failedStartupReader{}} {
		if copyCanonicalPreviousStartupSource(io.Discard, source) == nil {
			t.Fatal("accepted missing/short/failed source")
		}
	}
	if copyCanonicalPreviousStartupSource(nil, strings.NewReader("x")) == nil {
		t.Fatal("nil destination")
	}
	if e := copyCanonicalPreviousStartupSource(failedStartupWriter{}, strings.NewReader("x")); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("writer failure hidden", e)
	}
	for _, count := range []int64{canonicalPreviousStartupBytes, canonicalPreviousStartupBytes + 10} {
		r := new(zeroStartupReader)
		if copyCanonicalPreviousStartupSource(io.Discard, io.LimitReader(r, count)) == nil {
			t.Fatal("accepted wrong same-size or trailing bytes")
		}
		want := count
		if want > canonicalPreviousStartupBytes+1 {
			want = canonicalPreviousStartupBytes + 1
		}
		if r.read != want {
			t.Fatalf("unbounded read: %d want %d", r.read, want)
		}
	}
}

// Optional positive fixture is the original publisher release provided by the
// integration agent, streamed directly from ZIP without executing or extracting.
func TestCanonicalStartupSourceOriginalPublishedFixture(t *testing.T) {
	fixture := os.Getenv("USB_LINK_CANONICAL_PREVIOUS_ZIP")
	if fixture == "" {
		t.Skip("original published fixture not provided")
	}
	z, e := zip.OpenReader(fixture)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var source *zip.File
	for _, f := range z.File {
		if f.Name == "USB-Link-Setup-0.8.97.exe" {
			if source != nil {
				t.Fatal("ambiguous fixture")
			}
			source = f
		}
	}
	if source == nil {
		t.Fatal("fixture source absent")
	}
	r, e := source.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = copyCanonicalPreviousStartupSource(io.Discard, r); e != nil {
		t.Fatal(e)
	}
}

func TestStartupDependencyGatePreservesOnUnreadableOrExactTarget(t *testing.T) {
	target := `C:\Program Files\USB Link\0.8.97\USB-Link.exe`
	for _, path := range []string{target, `C:\Program Files\USB Link\0.8.96\USB-Link.exe`} {
		if startupDependencyRetentionReason(nil, path, errors.New("COM/source unproven")) == "" {
			t.Fatal("query failure permitted deletion")
		}
	}
	if startupDependencyRetentionReason([]string{strings.ToUpper(target)}, target, nil) == "" {
		t.Fatal("case-equivalent task target lost")
	}
	if startupDependencyRetentionReason([]string{target}, target+".other", nil) != "" {
		t.Fatal("prefix treated as exact dependency")
	}
	if startupDependencyRetentionReason(nil, target, nil) != "" {
		t.Fatal("successful absent task query preserved unrelated old source")
	}
}
