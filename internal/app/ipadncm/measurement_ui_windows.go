//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"time"
)

// Exercise the owned renderer's normal shutdown/show path while the network
// monitor stays running. Unlike modernUI.close, this preserves its UI lifetime.
func MeasurementUI(open bool) error {
	appWindows.Lock()
	var ui *modernUI
	for _, w := range appWindows.byHandle {
		if w.modern != nil {
			ui = w.modern
			break
		}
	}
	appWindows.Unlock()
	if ui == nil {
		return fmt.Errorf("owned desktop controller unavailable")
	}
	if open {
		if !ui.show("measurement-open") {
			return fmt.Errorf("desktop did not become ready")
		}
		return nil
	}
	ui.mu.Lock()
	if ui.cmd == nil {
		ui.mu.Unlock()
		return nil
	}
	done := ui.childDone
	closing := ui.cmd
	select {
	case ui.messages <- map[string]string{"event": "shutdown"}:
	default:
		ui.mu.Unlock()
		return fmt.Errorf("desktop control queue busy")
	}
	ui.mu.Unlock()
	select {
	case <-done:
		ui.mu.Lock()
		if ui.cmd == closing {
			ui.cmd = nil
			ui.input = nil
		}
		ui.mu.Unlock()
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("desktop shutdown not confirmed")
	}
}
