package macconnection

import "sync"

// A successful identity observation is invalidated by a coalesced device event.
// Registration failure or an unreadable inventory preserves live query behavior.
type rootObservation struct {
	sync.Mutex
	events <-chan struct{}
	valid  bool
	root   string
}

func (o *rootObservation) current(query func() (string, error), poll bool) string {
	o.Lock()
	defer o.Unlock()
	for o.events != nil {
		select {
		case <-o.events:
			o.valid = false
		default:
			goto checked
		}
	}
checked:
	if o.events == nil || poll || !o.valid {
		root, e := query()
		if e != nil {
			o.valid = false
			o.root = ""
			return ""
		}
		o.root = root
		o.valid = true
	}
	return o.root
}
