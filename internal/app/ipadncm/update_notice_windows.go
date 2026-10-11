//go:build windows && amd64

package ipadncm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

var updateNotices = struct {
	sync.Mutex
	pending map[string]updateNoticePending
}{pending: map[string]updateNoticePending{}}

type updateNoticePending struct {
	ui          *modernUI
	rendererPID int
	ack         chan struct{}
}

func acknowledgeUpdateNotice(ui *modernUI, rendererPID int, id string) {
	updateNotices.Lock()
	defer updateNotices.Unlock()
	if notice, ok := updateNotices.pending[id]; ok && notice.ui == ui && notice.rendererPID == rendererPID {
		delete(updateNotices.pending, id)
		close(notice.ack)
	}
}

// Receipt and installation both need a visible native notice and system sound,
// acknowledged by the owned renderer. A broken renderer cannot silently install.
func NotifyRemoteUpdate(version, phase string) error {
	return showRemoteUpdateNotice(context.Background(), version, phase, true)
}

// The authenticated service owns the installing visibility delay. This UI
// operation returns only after the actual owned renderer's window+sound ack.
func ShowRemoteUpdateNotice(ctx context.Context, version, phase string) error {
	if ctx == nil {
		return fmt.Errorf("invalid update notice context")
	}
	return showRemoteUpdateNotice(ctx, version, phase, false)
}
func showRemoteUpdateNotice(ctx context.Context, version, phase string, hold bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if phase != "received" && phase != "installing" {
		return fmt.Errorf("invalid update notice")
	}
	appWindows.Lock()
	var ui *modernUI
	for _, w := range appWindows.byHandle {
		if w.modern != nil {
			ui = w.modern
			break
		}
	}
	appWindows.Unlock()
	if ui == nil || !ui.show("update-"+phase) {
		return fmt.Errorf("native update notice unavailable")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	ack := make(chan struct{})
	ui.mu.Lock()
	messages, done, cmd := ui.messages, ui.childDone, ui.cmd
	ui.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("native update renderer unavailable")
	}
	updateNotices.Lock()
	updateNotices.pending[id] = updateNoticePending{ui: ui, rendererPID: cmd.Process.Pid, ack: ack}
	updateNotices.Unlock()
	defer func() { updateNotices.Lock(); delete(updateNotices.pending, id); updateNotices.Unlock() }()
	message := map[string]string{"event": "update-notice", "id": id, "update_version": version, "phase": phase}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case messages <- message:
	case <-timer.C:
		return fmt.Errorf("update notice delivery timeout")
	case <-done:
		return fmt.Errorf("renderer exited")
	case <-ctx.Done():
		return ctx.Err()
	case <-ui.ctx.Done():
		return fmt.Errorf("update notice cancelled")
	}
	select {
	case <-ack:
	case <-timer.C:
		return fmt.Errorf("update notice acknowledgement timeout")
	case <-done:
		return fmt.Errorf("renderer exited")
	case <-ctx.Done():
		return ctx.Err()
	case <-ui.ctx.Done():
		return fmt.Errorf("update notice cancelled")
	}
	if phase == "installing" && hold {
		// Keep the start notice visible before the installer exits its renderer.
		timer.Reset(3 * time.Second)
		select {
		case <-timer.C:
		case <-ui.ctx.Done():
			return fmt.Errorf("installation cancelled")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
