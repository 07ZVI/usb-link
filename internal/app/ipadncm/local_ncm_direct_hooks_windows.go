//go:build windows && amd64

package ipadncm

import "context"

// Only the tagged local selection creates an implementation. The ordinary
// Apple packet whitelist and all callers of the original entry point stay fixed.
type localNCMDirectAttempt interface {
	open(context.Context, Node, string) (modeControl, string, error)
	prepare(context.Context, Snapshot, []byte, func() bool) error
	observe(context.Context, *Result)
}

// Public builds cannot construct this target. Only its local implementation
// can admit the owned single-NCM layout; ordinary grouping stays unchanged.
type localDirectNetworkTarget interface {
	rootID() string
	driverKey() string
	mapping(Snapshot, string, func() []NetworkAdapter) (NetworkAdapter, string)
	runtimeEvidence(ApplicationResult)
	descriptorProof(Snapshot) bool
}
