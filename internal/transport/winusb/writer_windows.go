//go:build windows && amd64

package winusb

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/transport/usbwait"
	"time"
	"unsafe"
)

type writeSlot struct {
	request  *Read // Same pinned buffer/event ownership as overlapped IN.
	length   int
	started  time.Time
	observed chan struct{}
}

// Writer keeps a bounded FIFO of asynchronous OUT requests. Events and pinned
// buffers are allocated once and reused only after completion was collected.
// The caller is the sole owner; Close cancels/drains before unpinning.
type Writer struct {
	DiagnosticObserve                      func([]byte) func(time.Time)
	observer                               *usbwait.Waiter
	observerCancel                         context.CancelFunc
	DiagnosticSubmit, DiagnosticComplete   func([]byte, time.Time)
	device                                 *Interface
	pipe                                   byte
	slots                                  []writeSlot
	head, pending                          int
	Submitted, Completed, Bytes, WaitNanos uint64
	MaxPending                             int
	MaxCompletionNanos                     uint64
}

// Dormant outside authenticated latency sessions. A single cancellation event
// owns all diagnostic waiters; the OUT owner still collects in FIFO order.
func (w *Writer) EnableCompletionObservation(ctx context.Context, hook func([]byte) func(time.Time)) error {
	c, cancel := context.WithCancel(ctx)
	ready, err := usbwait.New(c)
	if err != nil {
		cancel()
		return err
	}
	w.observer = ready
	w.observerCancel = cancel
	w.DiagnosticObserve = hook
	return nil
}

func NewWriter(device *Interface, pipe byte, size, depth int) (*Writer, error) {
	if size < 1 || size > 65535 || depth < 1 || depth > 16 {
		return nil, fmt.Errorf("invalid USB write pool limits")
	}
	maxTransfer, err := device.PolicyUint(pipe, 8)
	if err != nil {
		return nil, err
	}
	if uint32(size) > maxTransfer {
		return nil, fmt.Errorf("write buffer exceeds advertised OUT maximum transfer")
	}
	w := &Writer{device: device, pipe: pipe}
	for j := 0; j < depth; j++ {
		r, err := NewRead(size)
		if err != nil {
			w.Close()
			return nil, err
		}
		w.slots = append(w.slots, writeSlot{request: r})
	}
	return w, nil
}

func (w *Writer) collect(ctx context.Context, block bool) (bool, error) {
	if w.pending == 0 {
		return false, nil
	}
	s := &w.slots[w.head]
	r := s.request
	var n uint32
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		// Completion status and byte count come from the same native call.
		// The pinned slot remains pending on every failure for Close to drain.
		err := windows.GetOverlappedResult(w.device.File, &r.Overlapped, &n, false)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
			return false, err
		}
		if time.Since(s.started) >= 2*time.Second {
			return false, fmt.Errorf("USB_OUT_COMPLETION_TIMEOUT: USB OUT completion exceeded 2s deadline")
		}
		if !block {
			return false, nil
		}
		if _, err = r.Ready(10); err != nil {
			return false, err
		}
	}
	r.pending = false
	if s.observed != nil {
		<-s.observed
		s.observed = nil
	}
	if int(n) != s.length {
		return false, fmt.Errorf("short pipelined write %d/%d", n, s.length)
	}
	completion := uint64(time.Since(s.started))
	if completion > w.MaxCompletionNanos {
		w.MaxCompletionNanos = completion
	}
	if w.DiagnosticComplete != nil {
		w.DiagnosticComplete(r.Buffer[:n], time.Now())
	}
	w.Completed++
	w.Bytes += uint64(n)
	w.head = (w.head + 1) % len(w.slots)
	w.pending--
	return true, nil
}

func (w *Writer) Poll(ctx context.Context) error {
	for w.pending > 0 {
		done, err := w.collect(ctx, false)
		if err != nil {
			return err
		}
		if !done {
			break
		}
	}
	return nil
}

func (w *Writer) Submit(ctx context.Context, b []byte) error {
	if len(w.slots) == 0 || len(b) == 0 || len(b) > len(w.slots[0].request.Buffer) {
		return fmt.Errorf("invalid pipelined write length")
	}
	if err := w.Poll(ctx); err != nil {
		return err
	}
	if w.pending == len(w.slots) {
		start := time.Now()
		_, err := w.collect(ctx, true)
		w.WaitNanos += uint64(time.Since(start))
		if err != nil {
			return err
		}
	}
	s := &w.slots[(w.head+w.pending)%len(w.slots)]
	r := s.request
	if r.pending {
		return fmt.Errorf("write slot still owned by USB")
	}
	copy(r.Buffer, b)
	if err := windows.ResetEvent(r.Overlapped.HEvent); err != nil {
		return err
	}
	r.Overlapped.Internal, r.Overlapped.InternalHigh = 0, 0
	s.length, s.started = len(b), time.Now()
	err := boolCall("WinUsb_WritePipe", w.device.Handle, uintptr(w.pipe), uintptr(unsafe.Pointer(&r.Buffer[0])), uintptr(len(b)), 0, uintptr(unsafe.Pointer(&r.Overlapped)))
	if err != nil && !isPending(err) {
		return err
	}
	if w.DiagnosticSubmit != nil {
		w.DiagnosticSubmit(r.Buffer[:len(b)], s.started)
	}
	if w.DiagnosticObserve != nil {
		if mark := w.DiagnosticObserve(r.Buffer[:len(b)]); mark != nil {
			s.observed = make(chan struct{})
			done := s.observed
			length := s.length
			go func() {
				defer close(done)
				ready, err := w.observer.Ready(r.Overlapped.HEvent, true)
				at := time.Now()
				if err != nil || !ready {
					return
				}
				var bytes uint32
				if windows.GetOverlappedResult(w.device.File, &r.Overlapped, &bytes, false) == nil && int(bytes) == length {
					mark(at)
				}
			}()
		}
	}
	r.pending = true
	w.pending++
	w.Submitted++
	if w.pending > w.MaxPending {
		w.MaxPending = w.pending
	}
	return nil
}

func (w *Writer) Close() {
	if w.observerCancel != nil {
		w.observerCancel()
	}
	// Cancellation wakes the diagnostic waiters. Join them while each native
	// event and OVERLAPPED remain valid; CloseReads closes those event handles.
	for i := range w.slots {
		if w.slots[i].observed != nil {
			<-w.slots[i].observed
		}
	}
	rs := make([]*Read, 0, len(w.slots))
	for _, s := range w.slots {
		rs = append(rs, s.request)
	}
	w.device.CloseReads(rs)
	if w.observer != nil {
		w.observer.Close()
		w.observer = nil
	}
	w.slots = nil
	w.pending = 0
}

// Flush collects every owned request without cancelling or reusing a pending slot.
func (w *Writer) Flush(ctx context.Context) error {
	for w.pending > 0 {
		if _, err := w.collect(ctx, true); err != nil {
			return err
		}
	}
	return nil
}
func (w *Writer) Pending() int { return w.pending }
