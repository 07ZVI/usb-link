//go:build windows && amd64

// Package usbwait owns a cancellation event shared by transport waiters.
package usbwait

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"sync"
	"sync/atomic"
	"time"
)

type Waiter struct {
	ctx            context.Context
	event          windows.Handle
	stop           func() bool
	done           chan struct{}
	once           sync.Once
	modeEvent      windows.Handle
	readMode       func(func()) bool
	unsubscribe    func()
	eventWaitCalls atomic.Uint64
	ioWakes        atomic.Uint64
	modeWakes      atomic.Uint64
	waiting        atomic.Bool
	waitStarted    atomic.Int64
}

func New(ctx context.Context) (*Waiter, error) {
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return nil, e
	}
	w := &Waiter{ctx: ctx, event: event, done: make(chan struct{})}
	w.stop = context.AfterFunc(ctx, func() { windows.SetEvent(event); close(w.done) })
	return w, nil
}

// NewMode follows a reversible runtime mode source. Separate waiters are used
// by each native worker: resetting one worker's event cannot consume another's
// mode transition. The source must serialize reset/read with notification.
func NewMode(ctx context.Context, read func(func()) bool, observe func(func()) func()) (*Waiter, error) {
	w, err := New(ctx)
	if err != nil {
		return nil, err
	}
	w.modeEvent, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		w.Close()
		return nil, err
	}
	w.readMode = read
	w.unsubscribe = observe(func() { windows.SetEvent(w.modeEvent) })
	return w, nil
}

// Current checks the latest mode before every wait. A transition returns to the
// caller to recheck actual receive/completion state, including lease expiry.
func (w *Waiter) Current(event windows.Handle) (bool, error) {
	if err := w.ctx.Err(); err != nil {
		return false, err
	}
	var resetErr error
	events := w.readMode(func() { resetErr = windows.ResetEvent(w.modeEvent) })
	if resetErr != nil {
		return false, resetErr
	}
	if !events {
		return w.Ready(event, false)
	}
	w.eventWaitCalls.Add(1)
	w.waitStarted.Store(time.Now().UnixNano())
	w.waiting.Store(true)
	defer w.waiting.Store(false)
	timeout := uint32(windows.INFINITE)
	v, err := windows.WaitForMultipleObjects([]windows.Handle{w.event, w.modeEvent, event}, false, timeout)
	if err != nil {
		return false, err
	}
	switch v {
	case windows.WAIT_OBJECT_0:
		if err := w.ctx.Err(); err != nil {
			return false, err
		}
		return false, context.Canceled
	case windows.WAIT_OBJECT_0 + 1:
		w.modeWakes.Add(1)
		return false, nil
	case windows.WAIT_OBJECT_0 + 2:
		w.ioWakes.Add(1)
		return true, nil
	}
	return false, fmt.Errorf("native mode wait result=%d", v)
}

// Diagnostics only counts opt-in native waits; baseline packet handling does
// not pay for per-packet atomics. No native handle or mutable buffer is exposed.
func (w *Waiter) Diagnostics() any {
	return map[string]any{"event_wait_calls": w.eventWaitCalls.Load(), "io_wakes": w.ioWakes.Load(), "mode_wakes": w.modeWakes.Load(), "waiting": w.waiting.Load(), "last_wait_started_unix_nano": w.waitStarted.Load()}
}

// Every calling worker must finish before Close. Cancellation wakes an infinite
// native wait without polling and never frees a pending I/O request or buffer.
func (w *Waiter) Ready(event windows.Handle, events bool) (bool, error) {
	if e := w.ctx.Err(); e != nil {
		return false, e
	}
	if !events {
		v, e := windows.WaitForSingleObject(event, 50)
		if e != nil {
			return false, e
		}
		if v == windows.WAIT_OBJECT_0 {
			return true, nil
		}
		if v == uint32(windows.WAIT_TIMEOUT) {
			return false, nil
		}
		return false, fmt.Errorf("native wait result=%d", v)
	}
	v, e := windows.WaitForMultipleObjects([]windows.Handle{event, w.event}, false, windows.INFINITE)
	if e != nil {
		return false, e
	}
	if v == windows.WAIT_OBJECT_0 {
		return true, nil
	}
	if v == windows.WAIT_OBJECT_0+1 {
		if e = w.ctx.Err(); e != nil {
			return false, e
		}
		return false, context.Canceled
	}
	return false, fmt.Errorf("native wait result=%d", v)
}
func (w *Waiter) Close() {
	w.once.Do(func() {
		if w.unsubscribe != nil {
			w.unsubscribe()
			w.unsubscribe = nil
		}
		if !w.stop() {
			<-w.done
		}
		windows.CloseHandle(w.event)
		if w.modeEvent != 0 {
			windows.CloseHandle(w.modeEvent)
		}
	})
}
