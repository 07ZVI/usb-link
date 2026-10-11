package ipadncm

import "sync/atomic"

var simplifiedNetworkConfigured atomic.Bool
var simplifiedNetworkFeatures atomic.Bool

func SimplifiedIPadNetworkConfigured() bool { return simplifiedNetworkConfigured.Load() }

// Migration stops on the first failed independent readback. The durable
// original remains the authority; grouping is deliberately not a step here.
func runLegacyIsolationMigration(portable, service, retire func() error) error {
	for _, step := range []func() error{portable, service, retire} {
		if e := step(); e != nil {
			return e
		}
	}
	return nil
}
