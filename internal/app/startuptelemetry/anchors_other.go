//go:build !windows || !amd64

package startuptelemetry

import "time"

func captureNativeAnchors() Anchors {
	return Anchors{CapturedAt: time.Now().UTC(), Boot: Anchor{Problem: "WINDOWS_NATIVE_ANCHOR_UNAVAILABLE"}, Logon: Anchor{Problem: "WINDOWS_NATIVE_ANCHOR_UNAVAILABLE"}, Process: Anchor{Problem: "WINDOWS_NATIVE_ANCHOR_UNAVAILABLE"}}
}
