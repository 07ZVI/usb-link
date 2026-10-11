package ipadncm

import "context"

// Only interactive authorization is serialized. cached must freshly verify
// identity, scope and existing consent; handled=true can also mean rejection.
type usbConsentGate struct{ slot chan struct{} }

func newUSBConsentGate() *usbConsentGate { return &usbConsentGate{slot: make(chan struct{}, 1)} }

func (g *usbConsentGate) run(ctx context.Context, cached func() (bool, bool), interactive func() bool) bool {
	if ctx == nil || ctx.Err() != nil || cached == nil || interactive == nil {
		return false
	}
	if allowed, handled := cached(); handled {
		return allowed && ctx.Err() == nil
	}
	select {
	case g.slot <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-g.slot }()
	if ctx.Err() != nil {
		return false
	}
	// A different attempt may have saved consent while this one waited.
	if allowed, handled := cached(); handled {
		return allowed && ctx.Err() == nil
	}
	if ctx.Err() != nil {
		return false
	}
	return interactive() && ctx.Err() == nil
}
