package dependencies

import (
	"context"
	"sync"
)

// Different components use distinct cache/tree names. Serialize the same
// component while allowing an available USB component to bypass a slow download
// or an official installer for another component. Waiting remains cancellable.
type assetWork struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
}

func (w *assetWork) slot(id string) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.slots == nil {
		w.slots = make(map[string]chan struct{})
	}
	if w.slots[id] == nil {
		w.slots[id] = make(chan struct{}, 1)
	}
	return w.slots[id]
}

func (w *assetWork) acquire(ctx context.Context, id string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slot := w.slot(id)
	select {
	case slot <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slot
			return nil, err
		}
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (w *assetWork) tryAcquire(id string) (func(), bool) {
	slot := w.slot(id)
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	default:
		return nil, false
	}
}
