//go:build !windows || !amd64

package netconfig

import "context"

func observeFirewallShadow(ctx context.Context, s FirewallShadowScope, owner func() error) FirewallShadowSample {
	return FirewallShadowSample{Status: "unsupported_platform"}
}
