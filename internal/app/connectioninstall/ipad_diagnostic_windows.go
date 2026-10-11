//go:build windows && amd64

package connectioninstall

import (
	"context"
	"fmt"
)

// Diagnostics are fixed actions behind the existing USB-only TLS/bearer gate.
// The iPad owner schedules them after its active session has fully cleaned up.
func (m *RemoteManager) SetIPadDiagnostic(f func(string) (any, error), busy func() bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipadDiagnostic, m.ipadDiagnosticBusy = f, busy
}

func (m *RemoteManager) runIPadDiagnostic(kind string) (any, error) {
	if kind == "USBSTARTUPON" || kind == "IPADWINTUNMODULEOFF" || kind == "IPADWINTUNMODULEON" {
		m.measurements.Lock()
		busy := m.measurements.parentCancel != nil || m.measurements.udpID != ""
		for _, j := range m.measurements.jobs {
			busy = busy || j.Status == "running"
		}
		if busy {
			m.measurements.Unlock()
			return nil, fmt.Errorf("measurement already active")
		}
		// Reserve the same slot as a parent capture, including the verified
		// task readback and protected preference save. The owner supplies the
		// bounded task context and cancels it on application shutdown.
		_, cancel := context.WithCancel(context.Background())
		m.measurements.parentCancel = cancel
		m.measurements.Unlock()
		defer func() {
			cancel()
			m.measurements.Lock()
			m.measurements.parentCancel = nil
			m.measurements.Unlock()
		}()
	}
	m.mu.Lock()
	f := m.ipadDiagnostic
	m.mu.Unlock()
	if f == nil {
		return nil, fmt.Errorf("iPad diagnostic owner unavailable")
	}
	return f(kind)
}

func (m *RemoteManager) ipadDiagnosticActive() bool {
	m.mu.Lock()
	f := m.ipadDiagnosticBusy
	m.mu.Unlock()
	return f != nil && f()
}
