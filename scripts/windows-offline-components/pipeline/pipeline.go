// Package pipeline coordinates the private offline bundle without Windows APIs.
package pipeline

import (
	"context"
	"errors"
	"time"
)

var ErrRebootRequired = errors.New("component installation requires restart")

type Component struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	State   string `json:"state"`
	Problem string `json:"problem,omitempty"`
}

type Report struct {
	Schema         int         `json:"schema"`
	StartedUTC     string      `json:"started_utc"`
	FinishedUTC    string      `json:"finished_utc"`
	Outcome        string      `json:"outcome"`
	RebootRequired bool        `json:"reboot_required"`
	Components     []Component `json:"components"`
}

type Actions struct {
	Verify  func(context.Context, Component) error
	Detect  func(context.Context, Component) (bool, error)
	Prepare func(context.Context, Component) error
}

// Run verifies the complete bundle before preparing anything. A failed or
// cancelled step leaves later components untouched; reruns detect earlier work.
func Run(ctx context.Context, components []Component, actions Actions, verifyOnly bool) (report Report) {
	report = Report{Schema: 1, StartedUTC: time.Now().UTC().Format(time.RFC3339), Outcome: "failed", Components: append([]Component(nil), components...)}
	defer func() { report.FinishedUTC = time.Now().UTC().Format(time.RFC3339) }()
	for i := range report.Components {
		report.Components[i].State, report.Components[i].Problem = "not-run", ""
	}
	fail := func(i int, e error) {
		report.Components[i].State, report.Components[i].Problem = "failed", e.Error()
	}
	for i, c := range report.Components {
		if e := ctx.Err(); e != nil {
			fail(i, e)
			return
		}
		if e := actions.Verify(ctx, c); e != nil {
			fail(i, e)
			return
		}
		report.Components[i].State = "verified"
	}
	if verifyOnly {
		report.Outcome = "verified"
		return
	}
	for i := range report.Components {
		report.Components[i].State = "not-run"
	}
	for i, c := range report.Components {
		if e := ctx.Err(); e != nil {
			fail(i, e)
			return
		}
		ready, e := actions.Detect(ctx, c)
		if e != nil {
			fail(i, e)
			return
		}
		if ready {
			report.Components[i].State = "reused"
			continue
		}
		if e = actions.Prepare(ctx, c); errors.Is(e, ErrRebootRequired) {
			report.Components[i].State, report.RebootRequired = "reboot-required", true
		} else if e != nil {
			fail(i, e)
			return
		} else {
			report.Components[i].State = "ready"
		}
	}
	report.Outcome = "ready"
	if report.RebootRequired {
		report.Outcome = "reboot-required"
	}
	return
}
