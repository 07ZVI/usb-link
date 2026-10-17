package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"
)

// Registration precedes creating either a renderer or a tray. Missing or
// malformed admission never creates a second interface.
func loginUIAdmission(data []byte) (admitted, confirmed bool) {
	var result struct {
		Admitted *bool `json:"admitted"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 1024 || d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Admitted == nil {
		return false, false
	}
	return *result.Admitted, true
}

// Both registration and snapshot failures preserve the verified installer
// drain/handoff path. Communication loss alone never closes a login UI.
func stopLoginUIForVerifiedReplacement(draining, handoff func() bool, stop func()) bool {
	if !draining() && !handoff() {
		return false
	}
	stop()
	return true
}

// A duplicate window does not complete migration. Keep the original
// bootstrap verifier until it reports completion, or cancellation preserves
// the caller's existing failure cleanup.
func confirmLoginUIBootstrap(ctx context.Context, ticks <-chan time.Time, pending func() (bool, error), confirm func()) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticks:
			p, err := pending()
			if err == nil && !p {
				return true
			}
			if p {
				confirm()
			}
		}
	}
}

// Only an authenticated, version-matched snapshot can supply this display.
// Pipe loss, a pending restoration, or another UI's ordinary quit is not exit
// authority for this login process.
func loginUIFollowExit(display json.RawMessage) bool {
	var result struct {
		Desktop struct {
			Exit struct {
				ID             string `json:"request_id"`
				Phase          string `json:"phase"`
				CloseFollowers bool   `json:"close_followers"`
			} `json:"program_exit"`
		} `json:"desktop"`
	}
	if json.Unmarshal(display, &result) != nil {
		return false
	}
	exit := result.Desktop.Exit
	return validProgramExitID(exit.ID) && exit.Phase == "ready" && exit.CloseFollowers
}
