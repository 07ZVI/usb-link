package probecontrol

import (
	"bytes"
	"sync"
)

const ReadyMarker = "READY_FOR_MAC"

// ReadyWriter watches only the owned probe's output. Initialization errors
// cannot make the launcher announce readiness. Line fragments are bounded.
type ReadyWriter struct {
	mu     sync.Mutex
	line   []byte
	ready  bool
	notify func()
}

func NewReadyWriter(notify func()) *ReadyWriter { return &ReadyWriter{notify: notify} }

func (w *ReadyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	show := false
	for _, b := range p {
		if b == '\n' {
			if !w.ready && bytes.HasSuffix(bytes.TrimSuffix(w.line, []byte{'\r'}), []byte(" "+ReadyMarker)) {
				w.ready, show = true, true
			}
			w.line = w.line[:0]
		} else if len(w.line) < 256*1024 {
			w.line = append(w.line, b)
		}
	}
	w.mu.Unlock()
	if show && w.notify != nil {
		w.notify()
	}
	return len(p), nil
}
