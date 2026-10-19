// Package fileshare keeps the selected-folder catalog used by Windows native SMB.
package fileshare

import "sync/atomic"

// State records whether USB file sharing is enabled for the connected devices.
type State struct {
	Enabled atomic.Bool
}

var USB State
