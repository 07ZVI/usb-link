// Package startupopt selects independent startup experiments. It does not
// grant permission to mutate an interface, run a service, or admit a device.
package startupopt

import (
	"fmt"
	"sync"
)

const (
	NativeNetwork         = "native_network"
	NativeTask            = "native_task"
	DADZero               = "dad_zero"
	PersistentConfig      = "persistent_config"
	ParallelPrepare       = "parallel_prepare"
	ResidentFirewall      = "resident_firewall"
	CombinedLegacyNetwork = "combined_legacy_network"
	FirewallShadow        = "firewall_shadow"
	WintunModuleHold      = "wintun_module_hold"
)

var state struct {
	sync.RWMutex
	configured bool
	options    map[string]bool
}

func valid(name string) bool {
	switch name {
	case NativeNetwork, NativeTask, DADZero, PersistentConfig, ParallelPrepare, ResidentFirewall, CombinedLegacyNetwork, FirewallShadow, WintunModuleHold:
		return true
	}
	return false
}

// Configure is called once by the verified executable before starting any
// owner or session. Process environments and UI strings cannot select modes.
// A changed mode requires a graceful new owner, never a mid-session switch.
func Configure(names []string) error {
	next := make(map[string]bool)
	for _, name := range names {
		if !valid(name) || next[name] {
			return fmt.Errorf("STARTUP_OPTION_INVALID")
		}
		next[name] = true
	}
	state.Lock()
	defer state.Unlock()
	if state.configured {
		return fmt.Errorf("STARTUP_OPTIONS_ALREADY_CONFIGURED")
	}
	state.options, state.configured = next, true
	return nil
}

func Enabled(name string) bool {
	state.RLock()
	defer state.RUnlock()
	return valid(name) && state.options[name]
}

func Snapshot() map[string]bool {
	state.RLock()
	defer state.RUnlock()
	out := make(map[string]bool)
	for _, name := range []string{NativeNetwork, NativeTask, DADZero, PersistentConfig, ParallelPrepare, ResidentFirewall, CombinedLegacyNetwork, FirewallShadow, WintunModuleHold} {
		out[name] = state.options[name]
	}
	return out
}
