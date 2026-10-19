package connectioninstall

import (
	"context"
	"fmt"
	"time"
)

// Budgets for verified older login clients asked to close during an upgrade.
// Clients that implement the installer close message exit within seconds. An
// older client that ignores it (0.10.53 to 0.10.57 show a confirmation window
// instead) is released by stopping the core, which that client already treats
// as a verified installer drain; nothing is killed.
const (
	installUICloseGrace = 5 * time.Second
	installUICloseTotal = 60 * time.Second
	installUIPoll       = 100 * time.Millisecond
)

// waitInstallationUIExit waits until every client reports exited. After grace
// it runs onGrace exactly once (stopping the core, whose restoration is the
// core's own job) and keeps waiting until total. A cancelled caller context or
// an exceeded total is INSTALL_UI_STILL_RUNNING; no process is ever terminated.
func waitInstallationUIExit(ctx context.Context, count int, exited func(i int) (bool, error), grace, total, poll time.Duration, onGrace func() error) error {
	wait, stop := context.WithTimeout(ctx, total)
	defer stop()
	start := time.Now()
	graceDone := false
	for i := 0; i < count; i++ {
		for {
			done, e := exited(i)
			if e != nil {
				return e
			}
			if done {
				break
			}
			if wait.Err() != nil {
				return fmt.Errorf("INSTALL_UI_STILL_RUNNING: 請關閉 USB Link 介面後重新執行同一安裝程式。 %w", wait.Err())
			}
			if !graceDone && onGrace != nil && time.Since(start) >= grace {
				graceDone = true
				if e := onGrace(); e != nil {
					return e
				}
			}
			select {
			case <-wait.Done():
			case <-time.After(poll):
			}
		}
	}
	return nil
}
