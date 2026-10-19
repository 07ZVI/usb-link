package ipadncm

import (
	"context"
	"sync"
	"time"
)

// The tray icon belongs to the status window's thread; only that thread may
// delete it. A process that ends first leaves a ghost icon in the notification
// area, so every exit path requests removal and waits (bounded) for the
// acknowledgement before the process is allowed to terminate.
const trayRemovalTimeout = 2 * time.Second

// trayRemovalAck is closed by the window thread once its icon is gone.
type trayRemovalAck struct {
	once sync.Once
	done chan struct{}
}

func newTrayRemovalAck() *trayRemovalAck { return &trayRemovalAck{done: make(chan struct{})} }
func (a *trayRemovalAck) release()       { a.once.Do(func() { close(a.done) }) }

// removeTraysAndWait posts a removal request for each ack and waits until all
// are released or the timeout passes. It reports whether every icon is gone.
func removeTraysAndWait(acks []*trayRemovalAck, post func(i int), timeout time.Duration) bool {
	for i := range acks {
		post(i)
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for _, a := range acks {
		select {
		case <-a.done:
		case <-deadline.C:
			return false
		}
	}
	return true
}

// removeTrayOnCancel requests removal as soon as ctx ends, before slower
// teardown (renderer join, restore) can delay it.
func removeTrayOnCancel(ctx context.Context, request func()) {
	go func() {
		<-ctx.Done()
		request()
	}()
}

// terminateAfterTrayRemoval sequences exit: removal first, termination after.
func terminateAfterTrayRemoval(remove func() bool, terminate func()) {
	remove()
	terminate()
}
