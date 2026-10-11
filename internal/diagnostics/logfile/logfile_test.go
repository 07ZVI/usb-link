package logfile

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentRuntimeLogsRemainBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "runtime.log")
	w, err := Open(p, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := w.Write(bytes.Repeat([]byte{'x'}, 100)); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err = w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{p, p + ".1"} {
		info, err := os.Stat(name)
		if err != nil || info.Size() > 2048 {
			t.Fatal(info, err)
		}
	}
	if _, err = w.Write([]byte("after close")); err == nil {
		t.Fatal("write after close accepted")
	}
}
