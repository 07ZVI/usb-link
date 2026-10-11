package netconfig

import "sync/atomic"

var residentFirewallSelection atomic.Bool

// Selected once by the verified owner before sessions start. This flag selects
// read/repair orchestration, never authorizes an adapter or a firewall write.
func SetResidentFirewallEnabled(v bool) { residentFirewallSelection.Store(v) }
func ResidentFirewallEnabled() bool     { return residentFirewallSelection.Load() }
